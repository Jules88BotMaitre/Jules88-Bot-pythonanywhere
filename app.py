from flask import Flask, request, session, redirect, url_for, make_response
import sqlite3
from requests_oauthlib import OAuth2Session
import os
import subprocess
import datetime
import json
import time
import threading
from zoneinfo import ZoneInfo
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect, generate_csrf
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import os
from dotenv import load_dotenv
load_dotenv ( os.path.join ( os.path.dirname ( os.path.abspath ( __file__ )  ) , '.env' ) )
VIKIDIA_OAUTH_CLIENT_ID = os.environ.get ( 'VIKIDIA_OAUTH_CLIENT_ID')
VIKIDIA_OAUTH_CLIENT_SECRET = os.environ.get ( 'VIKIDIA_OAUTH_CLIENT_SECRET')
VIKIDIA_OAUTH_AUTHORIZATION_URL = 'https://central.vikidia.org/w/rest.php/oauth2/authorize'
VIKIDIA_OAUTH_TOKEN_URL = 'https://central.vikidia.org/w/rest.php/oauth2/access_token'
VIKIDIA_OAUTH_PROFILE_URL = 'https://central.vikidia.org/w/rest.php/oauth2/resource/profile'
VIKIDIA_OAUTH_REDIRECT_URI = 'https://jules88.pythonanywhere.com/oauth/callback'
RECAPTCHA_SITE_KEY = os.environ.get ( 'RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET = os.environ.get ( 'RECAPTCHA_SECRET_KEY')
app = Flask ( __name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect ( app)
@app.route ( '/oauth/login')
def oauth_login (  ) :
    discord_id = request.args.get ( 'discord_id')
    if discord_id:
        session['pending_discord_id'] = discord_id

    vikidia = OAuth2Session ( VIKIDIA_OAUTH_CLIENT_ID, redirect_uri=VIKIDIA_OAUTH_REDIRECT_URI)
    authorization_url, state = vikidia.authorization_url ( VIKIDIA_OAUTH_AUTHORIZATION_URL)
    session['oauth_state'] = state
    return redirect ( authorization_url)

@app.route ( '/oauth/callback')
def oauth_callback (  ) :
    vikidia = OAuth2Session ( VIKIDIA_OAUTH_CLIENT_ID, state=session.get ( 'oauth_state' ) , redirect_uri=VIKIDIA_OAUTH_REDIRECT_URI)
    token = vikidia.fetch_token(
        VIKIDIA_OAUTH_TOKEN_URL,
        client_secret=VIKIDIA_OAUTH_CLIENT_SECRET,
        authorization_response=request.url
    )

    resp = vikidia.get ( VIKIDIA_OAUTH_PROFILE_URL)
    profile = resp.json ( )

    username = profile.get ( 'username')
    if not username:
        return "Erreur : impossible de récupérer le nom d'utilisateur Vikidia.", 400

    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    user = conn.execute ( "SELECT * FROM users WHERE vikidia_username = ?", (username, )  ) .fetchone ( )

    discord_id = session.pop ( 'pending_discord_id', None)

    discord_id_final = None
    user_est_nouveau = user is None

    if user_est_nouveau:
        conn.execute(
            "INSERT INTO users (username, password_hash, status, vikidia_username, discord_id) VALUES (?, ?, ?, ?, ? ) ",
            (username, '', 'en_attente', username, discord_id)
        )
        conn.commit ( )
        user_status = 'en_attente'
        # Compte tout neuf, en_attente : pas d'accès Discord tant que non validé.
    else:
        user_status = user['status']
        discord_id_final = user['discord_id']
        if discord_id and not user['discord_id']:
            conn.execute ( "UPDATE users SET discord_id = ? WHERE vikidia_username = ?", (discord_id, username ) )
            conn.commit ( )
            discord_id_final = discord_id

    conn.close ( )

    # Synchronise les autorisations Discord une fois la connexion ci-dessus bien refermée,
    # pour éviter un verrou de la base (sqlite3.OperationalError: database is locked ) .
    if not user_est_nouveau:
        synchroniser_autorisation_discord ( discord_id_final, username, user_status)

    session['username'] = username
    session.pop ( 'developer', None)

    # Le code d'autorisation Vikidia est à usage unique : si on affichait la
    # page directement ici, un simple rechargement du navigateur renverrait
    # le même code à Vikidia et provoquerait une InvalidClientIdError
    # ("invalid_request", code déjà consommé ) . On redirige donc vers / et on
    # affiche l'animation là-bas (schéma Post/Redirect/Get ) .
    session['juste_connecte'] = username
    return redirect ( url_for ( 'home' ) )
def champ_csrf (  ) :
    return f'<input type="hidden" name="csrf_token" value="{escape ( generate_csrf (  )  ) }">'

# ⚠️ Remplace cette clé par une longue chaîne aléatoire à toi (garde-la secrète)
app.secret_key = os.environ.get ( 'FLASK_SECRET_KEY')

# ⚠️ Mot de passe pour la connexion développeur ET pour déverrouiller le site
DEVELOPER_PASSWORD = os.environ.get ( 'DEVELOPER_PASSWORD')

# ⚠️ Ton numéro de téléphone, affiché uniquement aux comptes "confiance"
NUMERO_TELEPHONE_DEV = os.environ.get ( 'NUMERO_TELEPHONE_DEV', '')

# ⚠️ La "Clé publique" de ton application, visible sur le Developer Portal
# Discord (page "General Information" de ton application)
DISCORD_PUBLIC_KEY = os.environ.get ( 'DISCORD_PUBLIC_KEY')

BASE_DIR = os.path.dirname ( __file__)
DB_FILE = os.path.join ( BASE_DIR, "users.db")
LOG_FILE = os.path.join ( BASE_DIR, "bot_log.txt")

# Créé par le bot pendant qu'il tourne, supprimé dès qu'il s'arrête (quelle
# que soit la raison) — sert uniquement à afficher le statut en ligne/hors ligne.
EN_COURS_FILE = os.path.join ( BASE_DIR, "bot_en_cours.txt")

# Arrêt "normal" : le bot termine proprement l'étape en cours puis s'arrête.
# Ce fichier est auto-supprimé par le bot une fois l'arrêt honoré.
STOP_SOFT_FILE = os.path.join ( BASE_DIR, "arret_normal.txt")

# Verrouillage global : bloque TOUT le site (connexion, inscription, actions)
# jusqu'à ce que le développeur entre son mot de passe pour déverrouiller.
# C'est aussi ce fichier que le bot surveille pour un arrêt d'urgence définitif.
GLOBAL_LOCK_FILE = os.path.join ( BASE_DIR, "site_verrouille.txt")

# Endpoints Flask accessibles même quand le site est verrouillé
ENDPOINTS_AUTORISES_VERROUILLE = {"unlock", "static"}

# Maintenance : bloque tout le monde SAUF le développeur (qui garde un accès
# total ) . Contrairement au verrouillage d'urgence, personne ne peut la lever
# à part le développeur lui-même — pas de mot de passe à saisir pour les autres.
MAINTENANCE_FILE = os.path.join ( BASE_DIR, "maintenance.txt")
ENDPOINTS_AUTORISES_MAINTENANCE = {"developer_login", "static"}

# Feu vert/rouge : visible par les comptes confiance et le développeur
# uniquement. Vert (par défaut, fichier absent) = les comptes confiance
# peuvent lancer des scripts. Rouge = ils ne peuvent plus, tant que le
# développeur ne repasse pas au vert. Le développeur, lui, n'est jamais
# bloqué par ce feu.
FEU_FILE = os.path.join ( BASE_DIR, "feu_scripts.txt")


def lire_feu (  ) :
    if os.path.exists ( FEU_FILE ) :
        with open ( FEU_FILE, "r", encoding="utf-8") as f:
            valeur = f.read (  ) .strip ( )
        return valeur if valeur in ("vert", "rouge") else "vert"
    return "vert"


def definir_feu ( couleur ) :
    with open ( FEU_FILE, "w", encoding="utf-8") as f:
        f.write ( couleur)


# Annonce du développeur : affichée à la place/au-dessus du panneau de
# présentation, visible par TOUT LE MONDE (développeur, confiance,
# connecté, anonyme ) . Facultative : si le fichier n'existe pas, rien ne
# s'affiche.
ANNONCE_FILE = os.path.join ( BASE_DIR, "annonce.json")


def lire_annonce (  ) :
    if not os.path.exists ( ANNONCE_FILE ) :
        return None
    try:
        with open ( ANNONCE_FILE, "r", encoding="utf-8") as f:
            return json.load ( f)
    except (json.JSONDecodeError, OSError ) :
        return None


def definir_annonce ( titre, message ) :
    with open ( ANNONCE_FILE, "w", encoding="utf-8") as f:
        json.dump ( {"titre": titre, "message": message}, f, ensure_ascii=False)


def supprimer_annonce (  ) :
    if os.path.exists ( ANNONCE_FILE ) :
        os.remove ( ANNONCE_FILE)


# Cooldown entre deux lancements de script : 60 secondes après la FIN d'un
# script (pas depuis son lancement ) , tout le monde doit attendre avant d'en
# relancer un autre. Si le site passe en maintenance pendant ce délai, le
# temps de maintenance ne compte pas — on décale l'échéance d'autant.
COOLDOWN_FILE = os.path.join ( BASE_DIR, "cooldown_scripts.txt")
DUREE_COOLDOWN = 5  # secondes


def lire_echeance_cooldown (  ) :
    if not os.path.exists ( COOLDOWN_FILE ) :
        return None
    try:
        with open ( COOLDOWN_FILE, "r", encoding="utf-8") as f:
            return float ( f.read (  ) .strip (  ) )
    except (ValueError, OSError ) :
        return None


def definir_echeance_cooldown ( echeance ) :
    with open ( COOLDOWN_FILE, "w", encoding="utf-8") as f:
        f.write ( str ( echeance ) )


def _attendre_fin_script_et_demarrer_cooldown ( processus ) :
    """Tourne dans un thread séparé : attend que le script lancé se termine
    réellement, puis démarre le cooldown de 60 secondes à partir de CE
    moment-là (pas du moment du lancement ) ."""
    processus.wait ( )
    definir_echeance_cooldown ( time.time ( ) + DUREE_COOLDOWN)


# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------

def init_db (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    # Mode WAL : autorise des lectures pendant une écriture, ce qui règle la
    # grande majorité des "sqlite3.OperationalError: database is locked"
    # observés quand deux requêtes touchent la base en même temps.
    conn.execute ( "PRAGMA journal_mode=WAL")
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'connecte',
            voir_telephone INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Migration : si la base existait déjà avant l'ajout de cette colonne
    try:
        conn.execute ( "ALTER TABLE users ADD COLUMN voir_telephone INTEGER NOT NULL DEFAULT 0")
        conn.commit ( )
    except sqlite3.OperationalError:
        pass  # la colonne existe déjà
    try:
        conn.execute ( "ALTER TABLE users ADD COLUMN vikidia_username TEXT")
        conn.commit ( )
    except sqlite3.OperationalError:
        pass  # la colonne existe déjà
    try:
        conn.execute ( "ALTER TABLE users ADD COLUMN discord_id TEXT")
        conn.commit ( )
    except sqlite3.OperationalError:
        pass  # la colonne existe déjà
    conn.execute ( "CREATE UNIQUE INDEX IF NOT EXISTS idx_vikidia_username ON users ( vikidia_username ) ")
    conn.execute ( "CREATE UNIQUE INDEX IF NOT EXISTS idx_discord_id ON users ( discord_id ) ")
    conn.commit ( )
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            email TEXT NOT NULL,
            question TEXT NOT NULL,
            date_envoi TEXT NOT NULL
        )
    """)
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            fichier TEXT NOT NULL UNIQUE,
            actif INTEGER NOT NULL DEFAULT 1,
            demande_parametre INTEGER NOT NULL DEFAULT 0
        )
    """)
    try:
        conn.execute ( "ALTER TABLE scripts ADD COLUMN demande_parametre INTEGER NOT NULL DEFAULT 0")
        conn.commit ( )
    except sqlite3.OperationalError:
        pass  # la colonne existe déjà
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS comptes_supprimes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            motif TEXT NOT NULL,
            date_suppression TEXT NOT NULL
        )
    """)
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS avis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            etoiles INTEGER NOT NULL,
            commentaire TEXT,
            date_envoi TEXT NOT NULL
        )
    """)
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS discord_autorises (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            nom TEXT NOT NULL,
            date_ajout TEXT NOT NULL
        )
    """)
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS problemes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probleme TEXT NOT NULL,
            quoi TEXT NOT NULL,
            comment_arrive TEXT NOT NULL,
            email TEXT,
            username TEXT,
            statut TEXT NOT NULL DEFAULT 'en_attente',
            date_envoi TEXT NOT NULL
        )
    """)
    try:
        conn.execute ( "ALTER TABLE problemes ADD COLUMN username TEXT")
        conn.commit ( )
    except sqlite3.OperationalError:
        pass  # la colonne existe déjà
    conn.execute ( """
        CREATE TABLE IF NOT EXISTS historique_lancements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utilisateur TEXT NOT NULL,
            nom_script TEXT NOT NULL,
            fichier TEXT NOT NULL,
            origine TEXT NOT NULL DEFAULT 'site',
            date_envoi TEXT NOT NULL
        )
    """)
    conn.commit ( )
    conn.close ( )


init_db ( )


def heure_paris (  ) :
    return datetime.datetime.now ( ZoneInfo ( "Europe/Paris" ) )


def enregistrer_lancement ( utilisateur, nom_script, fichier, origine="site" ) :
    """Enregistre le lancement dans l'historique et dans la console du bot."""
    horodatage = heure_paris (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    nom_utilisateur = (utilisateur or "Utilisateur inconnu" ) [:100]
    nom_script = (nom_script or os.path.basename ( fichier) or "Script inconnu" ) [:150]
    fichier = os.path.basename ( fichier or "inconnu.py" ) [:200]
    origine = (origine or "site" ) [:40]

    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO historique_lancements (utilisateur, nom_script, fichier, origine, date_envoi) "
        "VALUES (?, ?, ?, ?, ? ) ",
        (nom_utilisateur, nom_script, fichier, origine, horodatage)
    )
    conn.commit ( )
    conn.close ( )

    # Rend aussi le lancement visible immédiatement dans la console du site.
    with open ( LOG_FILE, "a", encoding="utf-8") as f:
        f.write ( f"\n[{horodatage} — Paris] ▶ Lancement de « {nom_script} » par {nom_utilisateur} ({origine} ) .\n")


def lister_historique_lancements ( limite=100, decalage=0 ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    rows = conn.execute(
        "SELECT utilisateur, nom_script, fichier, origine, date_envoi "
        "FROM historique_lancements ORDER BY id DESC LIMIT ? OFFSET ?",
        (limite, decalage)
    ).fetchall ( )
    total = conn.execute ( "SELECT COUNT ( *) FROM historique_lancements" ) .fetchone (  ) [0]
    conn.close ( )
    return rows, total


def get_user ( username ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, username, password_hash, status, voir_telephone FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone ( )
    conn.close ( )
    return row


def creer_utilisateur ( username, password ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO users (username, password_hash, status) VALUES (?, ?, 'connecte' ) ",
        (username, generate_password_hash ( password ) )
    )
    conn.commit ( )
    conn.close ( )


def lister_utilisateurs (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute ( "SELECT username, status, voir_telephone FROM users ORDER BY username")
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def changer_statut ( username, nouveau_statut ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "UPDATE users SET status = ? WHERE username = ?", (nouveau_statut, username ) )
    conn.commit ( )
    conn.close ( )

    # Synchronise automatiquement les autorisations Discord avec le nouveau statut.
    discord_id = get_discord_id_utilisateur ( username)
    synchroniser_autorisation_discord ( discord_id, username, nouveau_statut)


def changer_autorisation_telephone ( username, autorise ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "UPDATE users SET voir_telephone = ? WHERE username = ?",
        (1 if autorise else 0, username)
    )
    conn.commit ( )
    conn.close ( )


def supprimer_utilisateur ( username, motif ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    discord_id = get_discord_id_utilisateur ( username)
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "DELETE FROM users WHERE username = ?", (username, ) )
    conn.execute(
        "INSERT INTO comptes_supprimes (username, motif, date_suppression) VALUES (?, ?, ? ) ",
        (username, motif, horodatage)
    )
    conn.commit ( )
    conn.close ( )
    if discord_id:
        supprimer_discord_autorise_par_discord_id ( discord_id)


def lister_comptes_supprimes (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT username, motif, date_suppression FROM comptes_supprimes ORDER BY id DESC"
    )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def enregistrer_avis ( username, etoiles, commentaire ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO avis (username, etoiles, commentaire, date_envoi) VALUES (?, ?, ?, ? ) ",
        (username, etoiles, commentaire, horodatage)
    )
    conn.commit ( )
    conn.close ( )


def lister_avis (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT username, etoiles, commentaire, date_envoi FROM avis ORDER BY id DESC"
    )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def lister_discord_autorises (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, discord_id, nom, date_ajout FROM discord_autorises ORDER BY nom"
    )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def ajouter_discord_autorise ( discord_id, nom ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO discord_autorises (discord_id, nom, date_ajout) VALUES (?, ?, ? ) ",
        (discord_id, nom, horodatage)
    )
    conn.commit ( )
    conn.close ( )


def supprimer_discord_autorise ( entree_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "DELETE FROM discord_autorises WHERE id = ?", (entree_id, ) )
    conn.commit ( )
    conn.close ( )


def est_discord_autorise ( discord_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT nom FROM discord_autorises WHERE discord_id = ?", (discord_id,)
    )
    row = cur.fetchone ( )
    conn.close ( )
    return row[0] if row else None


def get_discord_id_utilisateur ( username ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute ( "SELECT discord_id FROM users WHERE username = ?", (username, ) )
    row = cur.fetchone ( )
    conn.close ( )
    return row[0] if row and row[0] else None


def supprimer_discord_autorise_par_discord_id ( discord_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "DELETE FROM discord_autorises WHERE discord_id = ?", (discord_id, ) )
    conn.commit ( )
    conn.close ( )


def synchroniser_autorisation_discord ( discord_id, nom, statut ) :
    """Ajoute ou retire l'entrée dans discord_autorises selon le statut du compte lié.
    confiance/connecte -> autorisé automatiquement. en_attente -> retiré automatiquement."""
    if not discord_id:
        return
    if statut in ('confiance', 'connecte' ) :
        try:
            ajouter_discord_autorise ( discord_id, nom)
        except sqlite3.IntegrityError:
            pass  # déjà présent dans la liste
    else:
        supprimer_discord_autorise_par_discord_id ( discord_id)


def enregistrer_probleme ( probleme, quoi, comment_arrive, email, username ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "INSERT INTO problemes (probleme, quoi, comment_arrive, email, username, statut, date_envoi) "
        "VALUES (?, ?, ?, ?, ?, 'en_attente', ? ) ",
        (probleme, quoi, comment_arrive, email, username, horodatage)
    )
    conn.commit ( )
    nouvel_id = cur.lastrowid
    conn.close ( )
    return nouvel_id


def lister_problemes (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, probleme, quoi, comment_arrive, email, statut, date_envoi "
        "FROM problemes ORDER BY id DESC"
    )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def lister_mes_problemes ( username ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, probleme, statut, date_envoi FROM problemes WHERE username = ? ORDER BY id DESC",
        (username,)
    )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def get_probleme ( probleme_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, statut, date_envoi FROM problemes WHERE id = ?", (probleme_id,)
    )
    row = cur.fetchone ( )
    conn.close ( )
    return row


def changer_statut_probleme ( probleme_id, statut ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "UPDATE problemes SET statut = ? WHERE id = ?", (statut, probleme_id ) )
    conn.commit ( )
    conn.close ( )


def supprimer_probleme ( probleme_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "DELETE FROM problemes WHERE id = ?", (probleme_id, ) )
    conn.commit ( )
    conn.close ( )


def enregistrer_contact ( nom, email, question ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO contacts (nom, email, question, date_envoi) VALUES (?, ?, ?, ? ) ",
        (nom, email, question, horodatage)
    )
    conn.commit ( )
    conn.close ( )


def lister_contacts (  ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute ( "SELECT nom, email, question, date_envoi FROM contacts ORDER BY id DESC")
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def lister_scripts ( actifs_seulement=False ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    if actifs_seulement:
        cur = conn.execute(
            "SELECT id, nom, fichier, actif, demande_parametre FROM scripts WHERE actif = 1 ORDER BY nom"
        )
    else:
        cur = conn.execute(
            "SELECT id, nom, fichier, actif, demande_parametre FROM scripts ORDER BY nom"
        )
    rows = cur.fetchall ( )
    conn.close ( )
    return rows


def get_script ( script_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    cur = conn.execute(
        "SELECT id, nom, fichier, actif, demande_parametre FROM scripts WHERE id = ?", (script_id,)
    )
    row = cur.fetchone ( )
    conn.close ( )
    return row


def ajouter_script ( nom, fichier, demande_parametre=False ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute(
        "INSERT INTO scripts (nom, fichier, actif, demande_parametre) VALUES (?, ?, 1, ? ) ",
        (nom, fichier, 1 if demande_parametre else 0)
    )
    conn.commit ( )
    conn.close ( )


def changer_statut_script ( script_id, actif ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "UPDATE scripts SET actif = ? WHERE id = ?", (1 if actif else 0, script_id ) )
    conn.commit ( )
    conn.close ( )


def supprimer_script ( script_id ) :
    conn = sqlite3.connect ( DB_FILE, timeout=15)
    conn.execute ( "DELETE FROM scripts WHERE id = ?", (script_id, ) )
    conn.commit ( )
    conn.close ( )


def lancer_script ( fichier, parametre=None, utilisateur_lanceur=None, nom_script=None, origine='site' ) :
    """Lance un script Python déjà présent sur le serveur, en arrière-plan.
    Le fichier doit être dans le dossier du site (pas de sous-dossier, pas de chemin ) .
    Si un paramètre est fourni, il est passé en argument (sys.argv[1]) au script —
    transmis directement au processus, sans passer par un shell, donc sans risque
    d'injection de commande."""
    fichier = os.path.basename ( fichier)
    chemin = os.path.join ( BASE_DIR, fichier)
    if not fichier.endswith ( ".py") or not os.path.isfile ( chemin ) :
        return False
    commande = ["python3", chemin]
    if parametre:
        commande.append ( parametre)
    enregistrer_lancement(
        utilisateur_lanceur or "Utilisateur inconnu",
        nom_script or os.path.splitext ( fichier ) [0],
        fichier,
        origine
    )
    processus = subprocess.Popen ( commande, cwd=BASE_DIR)
    threading.Thread(
        target=_attendre_fin_script_et_demarrer_cooldown,
        args= ( processus, ) ,
        daemon=True
    ).start ( )
    return True


def require_dev ( f ) :
    @wraps ( f)
    def wrapper ( *args, **kwargs ) :
        if not session.get ( 'developer' ) :
            return redirect ( url_for ( 'developer_login' ) )
        return f ( *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Verrouillage global du site
# ---------------------------------------------------------------------------

def creer_verrouillage ( raison ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    with open ( GLOBAL_LOCK_FILE, 'w', encoding='utf-8') as f:
        f.write ( f"{raison} — le {horodatage}\n")


def lire_raison_verrouillage (  ) :
    if not os.path.exists ( GLOBAL_LOCK_FILE ) :
        return ""
    with open ( GLOBAL_LOCK_FILE, 'r', encoding='utf-8') as f:
        return f.read (  ) .strip ( )


def maintenance_active (  ) :
    return os.path.exists ( MAINTENANCE_FILE)


def activer_maintenance (  ) :
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    with open ( MAINTENANCE_FILE, 'w', encoding='utf-8') as f:
        f.write ( f"Maintenance activée le {horodatage}\n{time.time (  ) }\n")


def desactiver_maintenance (  ) :
    if not os.path.exists ( MAINTENANCE_FILE ) :
        return

    # Le temps passé en maintenance ne doit pas compter dans le cooldown
    # entre deux scripts : on décale l'échéance de cooldown de la durée
    # exacte de la maintenance, si elle était encore en cours.
    try:
        with open ( MAINTENANCE_FILE, 'r', encoding='utf-8') as f:
            lignes = f.read (  ) .splitlines ( )
        debut_unix = float ( lignes[1]) if len ( lignes) > 1 else None
    except (OSError, ValueError, IndexError ) :
        debut_unix = None

    if debut_unix:
        duree_maintenance = time.time ( ) - debut_unix
        echeance = lire_echeance_cooldown ( )
        if echeance and echeance > debut_unix:
            definir_echeance_cooldown ( echeance + duree_maintenance)

    os.remove ( MAINTENANCE_FILE)


@app.before_request
def verifier_blocages (  ) :
    # 1. Arrêt d'urgence : bloque absolument tout le monde, y compris le développeur
    if os.path.exists ( GLOBAL_LOCK_FILE) and request.endpoint not in ENDPOINTS_AUTORISES_VERROUILLE:
        return page_verrouillage ( )
    # 2. Maintenance : bloque tout le monde SAUF le développeur connecté
    if (maintenance_active ( ) and not session.get ( 'developer')
            and request.endpoint not in ENDPOINTS_AUTORISES_MAINTENANCE ) :
        return page_maintenance ( )



# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

PAGE_STYLE = """
    body {
        background-color: #1e5fbf;
        min-height: 100vh;
        margin: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        font-family: Arial, sans-serif;
        padding: 20px 0;
        box-sizing: border-box;
    }
    .topbar {
        width: 90%;
        max-width: 500px;
        display: flex;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: 8px;
        margin-bottom: 15px;
    }
    .btn-small {
        background-color: #f0f0f0;
        color: #222;
        padding: 8px 14px;
        border-radius: 8px;
        text-decoration: none;
        font-weight: bold;
        font-size: 13px;
        box-shadow: 0 2px 6px rgba ( 0,0,0,0.3 ) ;
        border: none;
        cursor: pointer;
    }
    .btn-dev { background-color: #333; color: white; }
    .btn-cadenas { background-color: #d32f2f; color: white; }
    .panel {
        background-color: #f0f0f0;
        border-radius: 15px;
        padding: 40px;
        box-shadow: 0 4px 12px rgba ( 0,0,0,0.4 ) ;
        text-align: center;
        max-width: 500px;
    }
    .warning-icon { font-size: 60px; margin-bottom: 10px; }
    .panel-texte { font-size: 15px; line-height: 1.5; color: #333; margin: 10px 0; }
    .panel-texte a { color: #1e5fbf; font-weight: bold; text-decoration: none; }
    .badge-statut {
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 14px;
        margin-bottom: 15px;
        box-shadow: 0 2px 6px rgba ( 0,0,0,0.3 ) ;
    }
    .badge-en-ligne { background-color: #d4f5d4; color: #1b5e20; }
    .badge-hors-ligne { background-color: #eeeeee; color: #555; }
    .main-text { font-size: 24px; font-weight: bold; color: #222; }
    .console-panel {
        background-color: #0c0c0c;
        border-radius: 10px;
        padding: 15px 20px;
        margin-top: 20px;
        box-shadow: 0 4px 12px rgba ( 0,0,0,0.4 ) ;
        font-family: "Courier New", monospace;
        font-size: 14px;
        color: #33ff33;
        width: 90%;
        max-width: 500px;
        height: 220px;
        overflow-y: auto;
        text-align: left;
        white-space: pre-wrap;
        word-break: break-word;
    }
    .boutons-controle {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: center;
        margin-top: 20px;
    }
    .btn-urgence, .btn-normal {
        border: none;
        padding: 14px 28px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 15px;
        box-shadow: 0 4px 12px rgba ( 0,0,0,0.4 ) ;
    }
    .btn-urgence { background-color: #d32f2f; color: white; }
    .btn-normal { background-color: #f5a623; color: #222; }
    .form-panel {
        background-color: #f0f0f0;
        border-radius: 15px;
        padding: 30px;
        box-shadow: 0 4px 12px rgba ( 0,0,0,0.4 ) ;
        max-width: 450px;
        width: 85%;
        margin-top: 40px;
    }
    .form-panel h2 { text-align: center; margin-top: 0; }
    .form-panel input, .form-panel textarea {
        width: 100%;
        padding: 10px;
        margin: 8px 0;
        border-radius: 6px;
        border: 1px solid #aaa;
        box-sizing: border-box;
        font-size: 15px;
        font-family: Arial, sans-serif;
    }
    .form-panel textarea { resize: vertical; min-height: 90px; }
    .form-panel button {
        width: 100%;
        padding: 12px;
        margin-top: 10px;
        border: none;
        border-radius: 8px;
        background-color: #1e5fbf;
        color: white;
        font-weight: bold;
        font-size: 15px;
    }
    .erreur { color: #c0392b; text-align: center; font-weight: bold; }
    .info { color: #1e5fbf; text-align: center; font-weight: bold; }
    .lien-retour { text-align: center; margin-top: 15px; }
    .lien-retour a { color: #1e5fbf; text-decoration: none; font-weight: bold; }
    .ligne-compte {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        padding: 10px 0;
        border-bottom: 1px solid #ddd;
    }
    .btn-accepter, .btn-refuser {
        border: none;
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 13px;
        color: white;
        cursor: pointer;
    }
    .btn-accepter { background-color: #2e7d32; margin-right: 4px; }
    .btn-refuser { background-color: #c0392b; }
    .telephone-box {
        background-color: #fdecea;
        border: 2px solid #d32f2f;
        border-radius: 10px;
        padding: 15px;
        margin-top: 20px;
        text-align: center;
        font-weight: bold;
        color: #c0392b;
    }
    .ligne-contact {
        padding: 10px 0;
        border-bottom: 1px solid #ddd;
        font-size: 14px;
    }
    .lock-screen {
        background-color: #7a0d0d;
        min-height: 100vh;
        width: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        font-family: Arial, sans-serif;
        padding: 20px;
        box-sizing: border-box;
    }
    .lock-titre {
        font-size: 42px;
        font-weight: bold;
        color: white;
        text-align: center;
        margin-bottom: 10px;
    }
    .lock-raison {
        color: #ffd6d6;
        text-align: center;
        margin-bottom: 30px;
        font-size: 15px;
    }
    .lock-panel {
        background-color: #f0f0f0;
        border-radius: 15px;
        padding: 30px;
        max-width: 400px;
        width: 85%;
        text-align: center;
    }
"""


def page_html ( contenu_body ) :
    return f"""
    <html>
    <head>
        <title>Mon Bot</title>
        <style>{PAGE_STYLE}</style>
    </head>
    <body>
        {contenu_body}
    </body>
    </html>
    """


def page_verrouillage ( erreur="" ) :
    raison = lire_raison_verrouillage ( )
    corps = f"""
    <div class="lock-screen">
        <div class="lock-titre">🔒 ARRÊT D'URGENCE</div>
        <div class="lock-raison">Le site est verrouillé.{ ( ' Raison : ' + escape ( raison ) ) if raison else ''}</div>
        <div class="lock-panel">
            <h2>Déverrouillage développeur</h2>
            {'<p class="erreur">' + erreur + '</p>' if erreur else ''}
            <form method="POST" action="/unlock">
                {champ_csrf (  ) }
                <input type="password" name="password" placeholder="Mot de passe développeur" required>
                <button type="submit">Déverrouiller le site</button>
            </form>
        </div>
    </div>
    """
    return page_html ( corps)


def page_maintenance (  ) :
    corps = """
    <div class="lock-screen" style="background-color: #8a5a00;">
        <div class="lock-titre">🔧 MAINTENANCE</div>
        <div class="lock-raison">
            Une maintenance majeure est en cours, pendant cette opération
            le site n'est pas accessible sauf pour le développeur.
        </div>
        <div class="lien-retour">
            <a href="/developer-login" style="color: #ffe6b3;">Connexion développeur</a>
        </div>
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Page d'accueil
# ---------------------------------------------------------------------------

@app.route ( '/')
def home (  ) :
    utilisateur = session.get ( 'username')
    est_dev = session.get ( 'developer', False)
    statut_utilisateur = None

    nom_juste_connecte = session.pop ( 'juste_connecte', None)
    if nom_juste_connecte:
        overlay_connexion = f"""
        <div id="overlay-connexion" style="position:fixed; top:0; left:0; width:100%; height:100%;
             background:#000; display:flex; align-items:center; justify-content:center;
             flex-direction:column; z-index:9999;">
            <video id="video-connexion" autoplay muted playsinline preload="auto"
                   style="max-width:100%; max-height:100%;">
                <source src="/static/videoplayback_500.mp4" type="video/mp4">
            </video>
            <div id="etape-succes" style="display:none; text-align:center; color:#fff; padding:20px;">
                <h2>✅ Connecté avec succès !</h2>
                <p>Ton compte Vikidia <strong>{escape ( nom_juste_connecte ) }</strong> est bien relié au site.</p>
                <button type="button" class="btn-small" onclick="document.getElementById ( 'overlay-connexion' ) .remove (  ) ;">Continuer</button>
            </div>
        </div>
        <script>
            var videoConnexion = document.getElementById ( 'video-connexion' ) ;
            videoConnexion.addEventListener ( 'ended', function () {{
                videoConnexion.style.display = 'none';
                document.getElementById ( 'etape-succes' ) .style.display = 'block';
            }} ) ;
            var lecture = videoConnexion.play (  ) ;
            if (lecture !== undefined) {{
                lecture.catch ( function () {{
                    document.addEventListener ( 'click', function relancer ( ) {{
                        videoConnexion.play (  ) ;
                        document.removeEventListener ( 'click', relancer ) ;
                    }}, {{ once: true }} ) ;
                }} ) ;
            }}
        </script>
        """
    else:
        overlay_connexion = ""

    if utilisateur:
        user = get_user ( utilisateur)
        if user:
            statut_utilisateur = user[3]

    if est_dev:
        maintenance_actif = maintenance_active ( )
        libelle_maintenance = "✅ Désactiver la maintenance" if maintenance_actif else "🔧 Maintenance"
        message_confirm_maintenance = (
            "Désactiver la maintenance et rouvrir le site à tous ?"
            if maintenance_actif else
            "Êtes-vous sûr de vouloir activer la maintenance ? Tous les comptes confiance et connecté seront bloqués, seul vous garderez l'accès."
        )
        feu_actuel = lire_feu ( )
        libelle_feu = "🔴 Passer au rouge" if feu_actuel == "vert" else "🟢 Repasser au vert"
        topbar = f"""
        <div class="topbar">
            <a href="/dev/comptes" class="btn-small">Comptes</a>
            <a href="/dev/contacts" class="btn-small">Messages contact</a>
            <a href="/dev/problemes" class="btn-small">Problèmes signalés</a>
            <a href="/dev/scripts" class="btn-small">Gérer scripts</a>
            <a href="/dev/lancements" class="btn-small">📋 Historique des lancements</a>
            <a href="/scripts" class="btn-small">Lancer scripts</a>
            <a href="/dev/discord" class="btn-small">Discord</a>
            <a href="/dev/annonce" class="btn-small">📢 Annonce</a>
            <a href="/contact" class="btn-small">Contact</a>
            <a href="/probleme" class="btn-small">⚠️ Problème</a>
            <a href="/avis" class="btn-small">Avis</a>
            <form method="POST" action="/dev/feu" style="display:inline;">
                {champ_csrf (  ) }
                <button type="submit" class="btn-small btn-cadenas">{libelle_feu}</button>
            </form>
            <form method="POST" action="/dev/maintenance" style="display:inline;"
                  onsubmit="return confirm ( '{message_confirm_maintenance}' ) ;">
                {champ_csrf (  ) }
                <button type="submit" class="btn-small btn-cadenas">{libelle_maintenance}</button>
            </form>
            <form method="POST" action="/dev/verrouiller" id="form-cadenas" style="display:inline;">
                {champ_csrf (  ) }
                <input type="hidden" name="raison" id="raison-cadenas" value="">
                <button type="button" class="btn-small btn-cadenas" onclick="verrouillerAvecMotif (  ) ">🔒</button>
            </form>
            <span class="btn-small btn-dev">🛠️ Mode développeur</span>
            <a href="/logout" class="btn-small">Déconnexion</a>
        </div>
        <script>
            function verrouillerAvecMotif ( ) {{
                const motif = prompt ( "Motif du verrouillage (visible sur l'écran de blocage) :", "" ) ;
                if (motif === null) return;
                document.getElementById ( 'raison-cadenas' ) .value = motif;
                document.getElementById ( 'form-cadenas' ) .submit (  ) ;
            }}
        </script>
        """
    elif utilisateur and statut_utilisateur == 'en_attente':
        topbar = f"""
        <div class="topbar">
            <span class="btn-small">Connecté : {escape ( utilisateur ) }</span>
            <a href="/logout" class="btn-small">Déconnexion</a>
        </div>
        """
    elif utilisateur:
        lien_scripts = '<a href="/scripts" class="btn-small">Scripts</a>' if statut_utilisateur == 'confiance' else ''
        topbar = f"""
        <div class="topbar">
            <span class="btn-small">Connecté : {escape ( utilisateur ) }</span>
            {lien_scripts}
            <a href="/contact" class="btn-small">Contact</a>
            <a href="/probleme" class="btn-small">⚠️ Problème</a>
            <a href="/avis" class="btn-small">Avis</a>
            <a href="/logout" class="btn-small">Déconnexion</a>
        </div>
        """
    else:
        topbar = """
        <div class="topbar">
            <a href="/oauth/login" class="btn-small">Se connecter avec Vikidia</a>
            <a href="/developer-login" class="btn-small btn-dev">Connexion développeur</a>
        </div>
        """

    boutons_controle = ""
    if statut_utilisateur == 'confiance' or est_dev:
        bouton_normal = f"""
        <form method="POST" action="/arret-normal">
            {champ_csrf (  ) }
            <button type="submit" class="btn-normal">⏸️ Arrêt normal</button>
        </form>
        """
        bouton_reinit = f"""
        <form method="POST" action="/reinitialiser"
              onsubmit="return confirm ( 'Vider la console et annuler une éventuelle pause ?' ) ;">
            {champ_csrf (  ) }
            <button type="submit" class="btn-normal">🔄 Réinitialiser</button>
        </form>
        """
        bouton_urgence = f"""
        <form method="POST" action="/emergency-stop"
              onsubmit="return confirm ( 'Confirmer l\\'arrêt d\\'urgence du robot ? Cela verrouillera tout le site.' ) ;">
            {champ_csrf (  ) }
            <button type="submit" class="btn-urgence">🛑 ARRÊT D'URGENCE</button>
        </form>
        """
        boutons_controle = f'<div class="boutons-controle">{bouton_normal}{bouton_reinit}{bouton_urgence}</div>'

    bot_en_ligne = os.path.exists ( EN_COURS_FILE)
    if bot_en_ligne:
        badge_statut = '<div class="badge-statut badge-en-ligne">🟢 Robot en ligne</div>'
    else:
        badge_statut = '<div class="badge-statut badge-hors-ligne">⚫ Robot hors ligne</div>'

    badge_feu = ""
    if statut_utilisateur == 'confiance' or est_dev:
        feu_actuel = lire_feu ( )
        if feu_actuel == "vert":
            badge_feu = '<div class="badge-statut badge-en-ligne">🟢 Feu vert : scripts autorisés</div>'
        else:
            badge_feu = '<div class="badge-statut badge-hors-ligne" style="background-color:#fdecea; color:#c0392b;">🔴 Feu rouge : scripts non autorisés</div>'

    annonce_actuelle = lire_annonce ( )
    if annonce_actuelle:
        panneau_principal = f"""
        <div class="panel" style="text-align:left;">
            <div class="warning-icon" style="text-align:center;">📢</div>
            <div class="main-text" style="text-align:center;">{escape ( annonce_actuelle['titre'] ) }</div>
            <p class="panel-texte" style="white-space:pre-wrap;">{escape ( annonce_actuelle['message'] ) }</p>
        </div>
        """
    elif utilisateur and statut_utilisateur == 'en_attente':
        panneau_principal = """
        <div class="panel" style="text-align:left;">
            <div class="warning-icon" style="text-align:center;">⏳</div>
            <div class="main-text" style="text-align:center;">Compte en attente</div>
            <p class="panel-texte">
                Ton compte est bien créé mais pas encore validé. Tu peux voir la console
                du robot ci-dessous, mais les sections Contact, ⚠️ Problème et Avis restent
                réservées aux comptes au statut <strong>confiance</strong> ou
                <strong>connecté</strong>. Patiente pendant la validation par le développeur.
            </p>
        </div>
        """
    else:
        panneau_principal = """
        <div class="panel" style="text-align:left;">
            <div class="warning-icon" style="text-align:center;">🤖</div>
            <div class="main-text" style="text-align:center;">Jules88!!Bot</div>
            <p class="panel-texte">
                Je suis un robot polyvalent : je ne m'occupe pas d'une seule catégorie
                en particulier (comme la maintenance ) , mais de plein de petites
                tâches différentes sur Vikidia.
            </p>
            <p class="panel-texte">
                Tu veux pouvoir lancer des scripts toi aussi ?
                <a href="/oauth/login">Connecte-toi avec Vikidia</a> dès maintenant !
            </p>
        </div>
        """

    corps = f"""
    {overlay_connexion}
    {topbar}
    {badge_statut}
    {badge_feu}
    {panneau_principal}
    <div class="console-panel" id="console">Chargement des logs...</div>
    {boutons_controle}

    <script>
        async function majConsole ( ) {{
            try {{
                const reponse = await fetch ( '/api/log' ) ;
                const donnees = await reponse.json (  ) ;
                const zone = document.getElementById ( 'console' ) ;
                zone.textContent = donnees.log || "Aucun log pour le moment.";
                zone.scrollTop = zone.scrollHeight;
            }} catch (e) {{
                document.getElementById ( 'console' ) .textContent = "Erreur de chargement des logs.";
            }}
        }}
        majConsole (  ) ;
        setInterval ( majConsole, 3000 ) ;
    </script>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Connexion / inscription
# ---------------------------------------------------------------------------

@app.route ( '/developer-login', methods=['GET', 'POST'])
def developer_login (  ) :
    erreur = ""
    if request.method == 'POST':
        password = request.form.get ( 'password', '')
        if password == DEVELOPER_PASSWORD:
            session['developer'] = True
            session.pop ( 'username', None)
            return redirect ( url_for ( 'home' ) )
        erreur = "Mot de passe développeur incorrect."

    corps = f"""
    <div class="form-panel">
        <h2>🛠️ Connexion développeur</h2>
        {'<p class="erreur">' + erreur + '</p>' if erreur else ''}
        <form method="POST">
            {champ_csrf (  ) }
            <input type="password" name="password" placeholder="Mot de passe développeur" required>
            <button type="submit">Entrer</button>
        </form>
        <div class="lien-retour"><a href="/">Retour au site</a></div>
    </div>
    """
    return page_html ( corps)


@app.route ( '/logout')
def logout (  ) :
    session.clear ( )
    return redirect ( url_for ( 'home' ) )


# ---------------------------------------------------------------------------
# Contact
# ---------------------------------------------------------------------------

def bloquer_si_pas_autorise (  ) :
    """Renvoie une réponse de redirection si le visiteur n'est ni connecté (confiance/connecté ) , ni développeur.
    Bloque : visiteurs anonymes ET comptes en_attente."""
    if session.get ( 'developer' ) :
        return None
    utilisateur = session.get ( 'username')
    if not utilisateur:
        return redirect ( url_for ( 'home' ) )
    user = get_user ( utilisateur)
    if not user or user[3] == 'en_attente':
        return redirect ( url_for ( 'home' ) )
    return None


@app.route ( '/contact', methods=['GET', 'POST'])
def contact (  ) :
    blocage = bloquer_si_pas_autorise ( )
    if blocage:
        return blocage

    succes = False
    erreur = ""
    if request.method == 'POST':
        nom = request.form.get ( 'nom', '' ) .strip ( )
        email = request.form.get ( 'email', '' ) .strip ( )
        question = request.form.get ( 'question', '' ) .strip ( )
        if not nom or not email or not question:
            erreur = "Merci de remplir tous les champs."
        else:
            enregistrer_contact ( nom, email, question)
            succes = True

    autorise_telephone = False
    utilisateur = session.get ( 'username')
    if session.get ( 'developer' ) :
        autorise_telephone = True
    elif utilisateur:
        user = get_user ( utilisateur)
        if user and user[4]:
            autorise_telephone = True

    bloc_telephone = ""
    if autorise_telephone:
        bloc_telephone = f"""
        <div class="telephone-box">
            📞 En cas de problème urgent, tu peux aussi appeler directement :<br>
            {escape ( NUMERO_TELEPHONE_DEV ) }
        </div>
        """

    if succes:
        corps = f"""
        <div class="form-panel">
            <h2>Message envoyé !</h2>
            <p class="info">Ta question a bien été envoyée.</p>
            {bloc_telephone}
            <div class="lien-retour"><a href="/">Retour au site</a></div>
        </div>
        """
        return page_html ( corps)

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Contact</h2>
        {'<p class="erreur">' + erreur + '</p>' if erreur else ''}
        <form method="POST">
            {champ_csrf (  ) }
            <input type="text" name="nom" placeholder="Ton nom" required>
            <input type="email" name="email" placeholder="Ton adresse mail" required>
            <textarea name="question" placeholder="Ta question" required></textarea>
            <button type="submit">Envoyer</button>
        </form>
        {bloc_telephone}
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Signalement de problème (accessible à tout le monde, même sans compte)
# ---------------------------------------------------------------------------

LABELS_STATUT_PROBLEME = {
    'en_attente': '⚪ En attente',
    'en_cours': '🟡 En cours',
    'fait': '🟢 Fait',
    'refus': '🔴 Refus',
}


@app.route ( '/probleme', methods=['GET', 'POST'])
def probleme (  ) :
    blocage = bloquer_si_pas_autorise ( )
    if blocage:
        return blocage

    utilisateur = session.get ( 'username')
    succes = False
    numero_suivi = None
    erreur = ""

    if request.method == 'POST':
        texte_probleme = request.form.get ( 'probleme', '' ) .strip ( )
        quoi = request.form.get ( 'quoi', '' ) .strip ( )
        comment_arrive = request.form.get ( 'comment_arrive', '' ) .strip ( )
        veut_reponse = request.form.get ( 'veut_reponse') == '1'
        email = request.form.get ( 'email', '' ) .strip ( )

        if not texte_probleme or not quoi or not comment_arrive:
            erreur = "Merci de remplir les trois champs sur le problème."
        elif veut_reponse and not email:
            erreur = "Merci d'indiquer ton adresse mail si tu veux une réponse."
        else:
            numero_suivi = enregistrer_probleme(
                texte_probleme, quoi, comment_arrive,
                email if veut_reponse else None, utilisateur
            )
            succes = True

    if succes:
        corps = f"""
        <div class="form-panel">
            <h2>Merci !</h2>
            <p class="info">Ton signalement a bien été envoyé.</p>
            <p style="text-align:center;">Ton numéro de suivi : <strong>#{numero_suivi}</strong>
            {' ( retrouvable aussi dans « Mes signalements » ci-dessous, puisque tu es connecté ) ' if utilisateur else "— note-le pour vérifier l'avancement plus tard"}</p>
            <div class="lien-retour"><a href="/">Retour au site</a></div>
        </div>
        """
        return page_html ( corps)

    # Numéro de suivi consulté via le formulaire de vérification
    resultat_suivi = ""
    numero_recherche = request.args.get ( 'numero', '' ) .strip ( )
    if numero_recherche:
        trouve = get_probleme ( numero_recherche) if numero_recherche.isdigit ( ) else None
        if trouve:
            _, statut_trouve, date_trouve = trouve
            resultat_suivi = f"""
            <p class="info">Signalement #{numero_recherche} — {LABELS_STATUT_PROBLEME.get ( statut_trouve, statut_trouve ) }
            (envoyé le {escape ( date_trouve ) } ) </p>
            """
        else:
            resultat_suivi = '<p class="erreur">Aucun signalement avec ce numéro.</p>'

    # Mes signalements (seulement si connecté)
    bloc_mes_signalements = ""
    if utilisateur:
        mes_problemes = lister_mes_problemes ( utilisateur)
        lignes_mes_problemes = ""
        for pid, texte_probleme, statut, date_envoi in mes_problemes:
            lignes_mes_problemes += f"""
            <div class="ligne-contact">
                #{pid} — {LABELS_STATUT_PROBLEME.get ( statut, statut ) } — {escape ( date_envoi ) }<br>
                {escape ( texte_probleme ) }
            </div>
            """
        if not mes_problemes:
            lignes_mes_problemes = "<p style='text-align:center; font-size:13px;'>Tu n'as encore rien signalé.</p>"
        bloc_mes_signalements = f"""
        <div class="form-panel">
            <h2>📋 Mes signalements</h2>
            {lignes_mes_problemes}
        </div>
        """
    else:
        bloc_mes_signalements = f"""
        <div class="form-panel">
            <h2>🔍 Vérifier un signalement</h2>
            <form method="GET">
                <input type="text" name="numero" placeholder="Numéro de suivi (ex: 12 ) " value="{escape ( numero_recherche ) }">
                <button type="submit">Vérifier</button>
            </form>
            {resultat_suivi}
        </div>
        """

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>⚠️ Signaler un problème</h2>
        {'<p class="erreur">' + erreur + '</p>' if erreur else ''}
        <form method="POST" id="form-probleme">
            {champ_csrf (  ) }
            <label style="font-size:13px; font-weight:bold;">Quel est le problème ?</label>
            <textarea name="probleme" placeholder="Décris le problème" required></textarea>

            <label style="font-size:13px; font-weight:bold;">Qu'est-ce qui se passe ?</label>
            <textarea name="quoi" placeholder="Ce qui se passe concrètement" required></textarea>

            <label style="font-size:13px; font-weight:bold;">Comment c'est arrivé ?</label>
            <textarea name="comment_arrive" placeholder="Les étapes qui ont mené au problème" required></textarea>

            <label style="display:block; text-align:left; font-size:13px; margin:10px 0;">
                <input type="checkbox" name="veut_reponse" value="1" id="case-reponse"
                       onchange="document.getElementById ( 'bloc-email' ) .style.display = this.checked ? 'block' : 'none';">
                📧 Je veux recevoir une réponse par mail
            </label>

            <div id="bloc-email" style="display:none;">
                <input type="email" name="email" placeholder="Ton adresse mail">
            </div>

            <button type="submit">Envoyer</button>
        </form>
    </div>
    {bloc_mes_signalements}
    """
    return page_html ( corps)


@app.route ( '/dev/problemes', methods=['GET', 'POST'])
@require_dev
def dev_problemes (  ) :
    if request.method == 'POST':
        probleme_id = request.form.get ( 'probleme_id')
        action = request.form.get ( 'action')
        if action == 'supprimer':
            supprimer_probleme ( probleme_id)
        elif action in ('en_attente', 'en_cours', 'fait', 'refus' ) :
            changer_statut_probleme ( probleme_id, action)
        return redirect ( url_for ( 'dev_problemes' ) )

    tous = lister_problemes ( )
    lignes = ""
    for probleme_id, texte_probleme, quoi, comment_arrive, email, statut, date_envoi in tous:
        bloc_email = f"📧 {escape ( email ) }" if email else "📧 <em>Pas de réponse demandée</em>"
        boutons_statut = ""
        for cle, label in LABELS_STATUT_PROBLEME.items (  ) :
            style_actif = "opacity:0.5;" if cle == statut else ""
            boutons_statut += f"""
            <button type="submit" name="action" value="{cle}" class="btn-accepter" style="{style_actif}">{label}</button>
            """
        lignes += f"""
        <div class="ligne-contact">
            <strong>#{probleme_id} — {LABELS_STATUT_PROBLEME.get ( statut, statut ) }</strong> — {escape ( date_envoi ) }<br>
            <b>Problème :</b> {escape ( texte_probleme ) }<br>
            <b>Ce qui se passe :</b> {escape ( quoi ) }<br>
            <b>Comment c'est arrivé :</b> {escape ( comment_arrive ) }<br>
            {bloc_email}
            <form method="POST" style="display:flex; gap:6px; flex-wrap:wrap; margin-top:8px;">
                {champ_csrf (  ) }
                <input type="hidden" name="probleme_id" value="{probleme_id}">
                {boutons_statut}
                <button type="submit" name="action" value="supprimer" class="btn-refuser"
                        onclick="return confirm ( 'Supprimer ce signalement ?' ) ;">🗑️ Supprimer</button>
            </form>
        </div>
        """
    if not tous:
        lignes = "<p style='text-align:center;'>Aucun problème signalé pour le moment.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Problèmes signalés</h2>
        {lignes}
    </div>
    """
    return page_html ( corps)


@app.route ( '/dev/contacts')
@require_dev
def dev_contacts (  ) :
    messages = lister_contacts ( )
    lignes = ""
    for nom, email, question, date_envoi in messages:
        lignes += f"""
        <div class="ligne-contact">
            <strong>{escape ( nom ) }</strong> ({escape ( email ) }) — {escape ( date_envoi ) }<br>
            {escape ( question ) }
        </div>
        """
    if not messages:
        lignes = "<p style='text-align:center;'>Aucun message pour le moment.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/dev/comptes" class="btn-small">Comptes</a>
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Messages du formulaire de contact</h2>
        {lignes}
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Avis (comptes connecté/confiance : donner un avis — développeur : les lire)
# ---------------------------------------------------------------------------

@app.route ( '/avis', methods=['GET', 'POST'])
def avis (  ) :
    blocage = bloquer_si_pas_autorise ( )
    if blocage:
        return blocage

    est_dev = session.get ( 'developer', False)

    if est_dev:
        tous_avis = lister_avis ( )
        lignes = ""
        for username, etoiles, commentaire, date_envoi in tous_avis:
            etoiles_affichees = "⭐" * etoiles + "☆" * (5 - etoiles)
            lignes += f"""
            <div class="ligne-contact">
                <strong>{escape ( username ) }</strong> — {etoiles_affichees} — {escape ( date_envoi ) }<br>
                {escape ( commentaire) if commentaire else "<em>Pas de commentaire</em>"}
            </div>
            """
        if not tous_avis:
            lignes = "<p style='text-align:center;'>Aucun avis pour le moment.</p>"

        corps = f"""
        <div class="topbar">
            <a href="/" class="btn-small">Retour au site</a>
        </div>
        <div class="form-panel">
            <h2>Avis déposés</h2>
            {lignes}
        </div>
        """
        return page_html ( corps)

    utilisateur = session.get ( 'username')
    if not utilisateur:
        return redirect ( url_for ( 'home' ) )

    succes = False
    erreur = ""
    if request.method == 'POST':
        etoiles = request.form.get ( 'etoiles', '')
        commentaire = request.form.get ( 'commentaire', '' ) .strip ( )
        if etoiles not in ('1', '2', '3', '4', '5' ) :
            erreur = "Merci de choisir une note de 1 à 5 étoiles."
        else:
            enregistrer_avis ( utilisateur, int ( etoiles ) , commentaire)
            succes = True

    if succes:
        corps = """
        <div class="form-panel">
            <h2>Merci pour ton avis !</h2>
            <p class="info">Ton avis a bien été envoyé.</p>
            <div class="lien-retour"><a href="/">Retour au site</a></div>
        </div>
        """
        return page_html ( corps)

    options_etoiles = ""
    for n in (5, 4, 3, 2, 1 ) :
        options_etoiles += f"""
        <label style="display:block; text-align:center; font-size:20px; margin:4px 0;">
            <input type="radio" name="etoiles" value="{n}" required> {"⭐" * n}
        </label>
        """

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Laisser un avis</h2>
        {'<p class="erreur">' + erreur + '</p>' if erreur else ''}
        <form method="POST">
            {champ_csrf (  ) }
            <p style="text-align:center;">Connecté en tant que : <strong>{escape ( utilisateur ) }</strong></p>
            {options_etoiles}
            <textarea name="commentaire" placeholder="Commentaire (facultatif ) "></textarea>
            <button type="submit">Envoyer</button>
        </form>
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Scripts (confiance + développeur)
# ---------------------------------------------------------------------------

@app.route ( '/scripts')
def scripts (  ) :
    utilisateur = session.get ( 'username')
    est_dev = session.get ( 'developer', False)
    statut_utilisateur = None
    if utilisateur:
        user = get_user ( utilisateur)
        if user:
            statut_utilisateur = user[3]

    if statut_utilisateur != 'confiance' and not est_dev:
        return redirect ( url_for ( 'home' ) )

    feu_actuel = lire_feu ( )
    feu_bloque = feu_actuel == "rouge" and not est_dev

    message = request.args.get ( 'message', '')
    # Le développeur voit tous les scripts, même désactivés ; les comptes
    # confiance ne voient que ceux activés.
    disponibles = lister_scripts ( actifs_seulement=not est_dev)
    lignes = ""
    for script_id, nom, fichier, actif, demande_parametre in disponibles:
        etiquette_inactif = " (⚪ désactivé ) " if not actif and est_dev else ""
        if feu_bloque:
            lignes += f"""
            <div class="ligne-compte">
                <span>{escape ( nom ) }{etiquette_inactif}</span>
                <span style="color:#c0392b; font-size:13px;">🔴 Non autorisé pour le moment</span>
            </div>
            """
        elif demande_parametre:
            lignes += f"""
            <div class="ligne-compte" style="flex-direction:column; align-items:stretch;">
                <span style="margin-bottom:6px;">{escape ( nom ) }{etiquette_inactif}</span>
                <form method="POST" action="/scripts/lancer"
                      onsubmit="return confirm ( 'Lancer le script « {escape ( nom ) } » ?' ) ;"
                      style="display:flex; gap:6px;">
                    {champ_csrf (  ) }
                    <input type="hidden" name="script_id" value="{script_id}">
                    <input type="text" name="parametre" placeholder="Nom de la page à analyser" required
                           style="flex:4; width:auto; min-width:0; padding:8px; border-radius:6px; border:1px solid #aaa; font-size:14px;">
                    <button type="submit" class="btn-accepter" style="flex:0 0 auto; width:auto; padding:6px 10px; font-size:12px; white-space:nowrap;">▶️ Lancer</button>
                </form>
            </div>
            """
        else:
            lignes += f"""
            <div class="ligne-compte">
                <span>{escape ( nom ) }{etiquette_inactif}</span>
                <form method="POST" action="/scripts/lancer"
                      onsubmit="return confirm ( 'Lancer le script « {escape ( nom ) } » ?' ) ;">
                    {champ_csrf (  ) }
                    <input type="hidden" name="script_id" value="{script_id}">
                    <button type="submit" class="btn-accepter">▶️ Valider et lancer</button>
                </form>
            </div>
            """
    if not disponibles:
        lignes = "<p style='text-align:center;'>Aucun script disponible pour le moment.</p>"

    lien_gestion = '<a href="/dev/scripts" class="btn-small">Gérer les scripts</a>' if est_dev else ''
    bandeau_feu = ""
    if feu_actuel == "rouge":
        bandeau_feu = (
            '<p class="erreur">🔴 Le feu est actuellement au rouge'
            + (' (tu restes autorisé en tant que développeur ) .' if est_dev else ' : personne ne peut lancer de script pour le moment.')
            + '</p>'
        )
    corps = f"""
    <div class="topbar">
        {lien_gestion}
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Scripts disponibles</h2>
        {bandeau_feu}
        {'<p class="info">' + escape ( message) + '</p>' if message else ''}
        {lignes}
    </div>
    """
    return page_html ( corps)


@app.route ( '/scripts/lancer', methods=['POST'])
def scripts_lancer (  ) :
    utilisateur = session.get ( 'username')
    est_dev = session.get ( 'developer', False)
    statut_utilisateur = None
    if utilisateur:
        user = get_user ( utilisateur)
        if user:
            statut_utilisateur = user[3]

    if statut_utilisateur != 'confiance' and not est_dev:
        return redirect ( url_for ( 'home' ) )

    if lire_feu ( ) == "rouge" and not est_dev:
        return redirect ( url_for ( 'scripts', message="🔴 Le feu est au rouge, aucun script ne peut être lancé pour le moment." ) )

    echeance_cooldown = lire_echeance_cooldown ( )
    if echeance_cooldown and time.time ( ) < echeance_cooldown:
        secondes_restantes = int ( echeance_cooldown - time.time (  ) ) + 1
        return redirect ( url_for ( 'scripts', message=f"⏳ Merci d'attendre encore {secondes_restantes} seconde ( s) avant de relancer un script." ) )

    script_id = request.form.get ( 'script_id')
    script = get_script ( script_id)
    # Le développeur peut lancer même un script désactivé (pour tester) ;
    # un compte confiance doit se limiter aux scripts activés.
    if not script or (not script[3] and not est_dev ) :
        return redirect ( url_for ( 'scripts', message="Script introuvable ou désactivé." ) )

    demande_parametre = script[4]
    parametre = request.form.get ( 'parametre', '' ) .strip ( ) if demande_parametre else None
    if demande_parametre and not parametre:
        return redirect ( url_for ( 'scripts', message="Merci de remplir le champ demandé." ) )

    lanceur = "Développeur" if est_dev else utilisateur
    ok = lancer_script(
        script[2], parametre,
        utilisateur_lanceur=lanceur,
        nom_script=script[1],
        origine="site"
    )
    message = "Script lancé !" if ok else "Erreur : fichier introuvable sur le serveur."
    return redirect ( url_for ( 'scripts', message=message ) )


@app.route ( '/dev/lancements')
@require_dev
def dev_historique_lancements (  ) :
    try:
        page = max ( 1, int ( request.args.get ( 'page', '1' )  ) )
    except (TypeError, ValueError ) :
        page = 1
    par_page = 50
    historique, total = lister_historique_lancements ( par_page, (page - 1) * par_page)
    lignes = ""
    for utilisateur, nom_script, fichier, origine, date_envoi in historique:
        lignes += f"""
        <div class="ligne-contact">
            <strong>👤 {escape ( utilisateur ) }</strong><br>
            📜 Script : {escape ( nom_script ) } <span style="color:#666;"> ( {escape ( fichier ) } ) </span><br>
            🕒 {escape ( date_envoi ) } — heure de Paris<br>
            <span style="color:#666;">Origine : {escape ( origine ) }</span>
        </div>
        """
    if not lignes:
        lignes = "<p style='text-align:center;'>Aucun lancement enregistré pour le moment.</p>"

    total_pages = max ( 1, (total + par_page - 1) // par_page)
    navigation = ""
    if page > 1:
        navigation += f'<a class="btn-small" href="/dev/lancements?page={page - 1}">← Plus récents</a> '
    if page < total_pages:
        navigation += f'<a class="btn-small" href="/dev/lancements?page={page + 1}">Plus anciens →</a>'

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>📋 Historique des lancements</h2>
        <p style="text-align:center;">{total} lancement ( s) enregistré ( s) — heure de Paris</p>
        {lignes}
        <div class="boutons-controle">{navigation}</div>
    </div>
    """
    return page_html ( corps)


@app.route ( '/dev/scripts', methods=['GET', 'POST'])
@require_dev
def dev_scripts (  ) :
    message = ""
    if request.method == 'POST':
        action = request.form.get ( 'action')
        if action == 'ajouter':
            nom = request.form.get ( 'nom', '' ) .strip ( )
            fichier = os.path.basename ( request.form.get ( 'fichier', '' ) .strip (  ) )
            demande_parametre = request.form.get ( 'demande_parametre') == '1'
            if not nom or not fichier.endswith ( '.py' ) :
                message = "Merci d'indiquer un nom et un fichier .py valide."
            elif not os.path.isfile ( os.path.join ( BASE_DIR, fichier )  ) :
                message = f"Le fichier '{fichier}' n'existe pas dans le dossier du site."
            else:
                try:
                    ajouter_script ( nom, fichier, demande_parametre)
                    message = "Script ajouté."
                except sqlite3.IntegrityError:
                    message = "Ce fichier est déjà enregistré."
        elif action == 'activer':
            changer_statut_script ( request.form.get ( 'script_id' ) , True)
        elif action == 'desactiver':
            changer_statut_script ( request.form.get ( 'script_id' ) , False)
        elif action == 'supprimer':
            supprimer_script ( request.form.get ( 'script_id' ) )
        return redirect ( url_for ( 'dev_scripts' ) )

    tous = lister_scripts ( )
    lignes = ""
    for script_id, nom, fichier, actif, demande_parametre in tous:
        etat = "🟢 Activé (visible pour les comptes confiance ) " if actif else "⚪ Désactivé"
        parametre_info = " — 📝 demande un paramètre" if demande_parametre else ""
        bouton_toggle = f"""
        <button type="submit" name="action" value="{'desactiver' if actif else 'activer'}" class="btn-refuser">
            {'Désactiver' if actif else 'Activer'}
        </button>
        """
        lignes += f"""
        <div class="ligne-compte">
            <span>{escape ( nom ) } ({escape ( fichier ) }) — {etat}{parametre_info}</span>
            <form method="POST" style="display:inline;">
                {champ_csrf (  ) }
                <input type="hidden" name="script_id" value="{script_id}">
                {bouton_toggle}
                <button type="submit" name="action" value="supprimer" class="btn-refuser"
                        onclick="return confirm ( 'Supprimer ce script de la liste ?' ) ;">🗑️</button>
            </form>
        </div>
        """
    if not tous:
        lignes = "<p style='text-align:center;'>Aucun script enregistré.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/dev/comptes" class="btn-small">Comptes</a>
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Gestion des scripts</h2>
        {'<p class="info">' + escape ( message) + '</p>' if message else ''}
        {lignes}
        <hr>
        <h2>Ajouter un script</h2>
        <p style="font-size:13px;">Le fichier .py doit déjà être présent dans le dossier du site
        (envoyé via l'onglet "Files" de PythonAnywhere ) .</p>
        <form method="POST">
            {champ_csrf (  ) }
            <input type="hidden" name="action" value="ajouter">
            <input type="text" name="nom" placeholder="Nom affiché (ex: Correction Portail ) " required>
            <input type="text" name="fichier" placeholder="Nom exact du fichier (ex: bot_portail.py ) " required>
            <label style="display:block; text-align:left; font-size:13px; margin:8px 0;">
                <input type="checkbox" name="demande_parametre" value="1">
                📝 Ce script demande un paramètre texte (ex : nom d'une page) avant de se lancer
            </label>
            <button type="submit">Ajouter</button>
        </form>
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Discord : liste des IDs autorisés à lancer des scripts via /lancer
# ---------------------------------------------------------------------------

@app.route ( '/dev/discord', methods=['GET', 'POST'])
@require_dev
def dev_discord (  ) :
    message = ""
    if request.method == 'POST':
        action = request.form.get ( 'action')
        if action == 'ajouter':
            discord_id = request.form.get ( 'discord_id', '' ) .strip ( )
            nom = request.form.get ( 'nom', '' ) .strip ( )
            if not discord_id.isdigit ( ) or not nom:
                message = "Merci d'indiquer un ID Discord valide (uniquement des chiffres) et un nom."
            else:
                try:
                    ajouter_discord_autorise ( discord_id, nom)
                    message = "Personne ajoutée."
                except sqlite3.IntegrityError:
                    message = "Cet ID Discord est déjà autorisé."
        elif action == 'supprimer':
            supprimer_discord_autorise ( request.form.get ( 'entree_id' ) )
        return redirect ( url_for ( 'dev_discord' ) )

    autorises = lister_discord_autorises ( )
    lignes = ""
    for entree_id, discord_id, nom, date_ajout in autorises:
        lignes += f"""
        <div class="ligne-compte">
            <span>{escape ( nom ) } — <code>{escape ( discord_id ) }</code></span>
            <form method="POST" style="display:inline;">
                {champ_csrf (  ) }
                <input type="hidden" name="entree_id" value="{entree_id}">
                <button type="submit" name="action" value="supprimer" class="btn-refuser"
                        onclick="return confirm ( 'Retirer {escape ( nom ) } de la liste ?' ) ;">🗑️ Retirer</button>
            </form>
        </div>
        """
    if not autorises:
        lignes = "<p style='text-align:center;'>Personne n'est encore autorisé.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/dev/scripts" class="btn-small">Gérer scripts</a>
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Autorisations Discord</h2>
        <p style="font-size:13px;">Seules les personnes listées ici peuvent lancer un script via la
        commande <code>/lancer</code> sur Discord. Pour trouver l'ID Discord de quelqu'un : mode développeur
        activé dans Discord (Paramètres > Avancés > Mode développeur ) , puis clic droit sur son pseudo > "Copier l'ID".</p>
        {'<p class="info">' + escape ( message) + '</p>' if message else ''}
        {lignes}
        <hr>
        <h2>Autoriser quelqu'un</h2>
        <form method="POST">
            {champ_csrf (  ) }
            <input type="hidden" name="action" value="ajouter">
            <input type="text" name="nom" placeholder="Nom ou pseudo (pour t'y retrouver ) " required>
            <input type="text" name="discord_id" placeholder="ID Discord (uniquement des chiffres ) " required>
            <button type="submit">Autoriser</button>
        </form>
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Annonce du développeur (visible par tout le monde sur l'accueil)
# ---------------------------------------------------------------------------

@app.route ( '/dev/annonce', methods=['GET', 'POST'])
@require_dev
def dev_annonce (  ) :
    message = ""
    if request.method == 'POST':
        action = request.form.get ( 'action')
        if action == 'supprimer':
            supprimer_annonce ( )
            message = "Annonce retirée."
        else:
            titre = request.form.get ( 'titre', '' ) .strip ( )
            texte_message = request.form.get ( 'message', '' ) .strip ( )
            if not titre or not texte_message:
                message = "Merci de remplir le titre et le message."
            else:
                definir_annonce ( titre, texte_message)
                message = "Annonce enregistrée."
        if not message.startswith ( "Merci" ) :
            return redirect ( url_for ( 'dev_annonce' ) )

    annonce_actuelle = lire_annonce ( )
    titre_actuel = escape ( annonce_actuelle["titre"]) if annonce_actuelle else ""
    message_actuel = escape ( annonce_actuelle["message"]) if annonce_actuelle else ""

    bloc_supprimer = ""
    if annonce_actuelle:
        bloc_supprimer = f"""
        <form method="POST" style="margin-top:10px;"
              onsubmit="return confirm ( 'Retirer l\\'annonce actuelle ?' ) ;">
            {champ_csrf (  ) }
            <input type="hidden" name="action" value="supprimer">
            <button type="submit" class="btn-refuser" style="width:100%;">🗑️ Retirer l'annonce</button>
        </form>
        """

    corps = f"""
    <div class="topbar">
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>📢 Annonce</h2>
        <p style="font-size:13px;">Visible par tout le monde (toi, comptes confiance, comptes connecté,
        et les visiteurs sans compte ) , à la place du panneau de présentation sur l'accueil. Les emojis
        sont autorisés. Laisse vide / retire-la si tu ne veux rien afficher.</p>
        {'<p class="info">' + escape ( message) + '</p>' if message else ''}
        <form method="POST">
            {champ_csrf (  ) }
            <input type="text" name="titre" placeholder="Titre de l'annonce" value="{titre_actuel}" required>
            <textarea name="message" placeholder="Message (emojis autorisés ) " required>{message_actuel}</textarea>
            <button type="submit">Enregistrer l'annonce</button>
        </form>
        {bloc_supprimer}
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Gestion des comptes (développeur)
# ---------------------------------------------------------------------------

@app.route ( '/dev/comptes', methods=['GET', 'POST'])
@require_dev
def dev_comptes (  ) :
    if request.method == 'POST':
        username = request.form.get ( 'username')
        action = request.form.get ( 'action')
        if action == 'supprimer':
            motif = request.form.get ( 'motif', '' ) .strip ( )
            if motif:
                supprimer_utilisateur ( username, motif)
            return redirect ( url_for ( 'dev_comptes' ) )
        if action == 'telephone':
            autorise = request.form.get ( 'autorise') == '1'
            changer_autorisation_telephone ( username, autorise)
            return redirect ( url_for ( 'dev_comptes' ) )
        nouveau_statut = request.form.get ( 'nouveau_statut')
        if nouveau_statut in ('connecte', 'confiance' ) :
            changer_statut ( username, nouveau_statut)
        return redirect ( url_for ( 'dev_comptes' ) )

    comptes = lister_utilisateurs ( )
    labels = {'connecte': '🔵 Connecté', 'confiance': '⭐ Confiance'}
    lignes = ""
    for username, status, voir_telephone in comptes:
        coche = "checked" if voir_telephone else ""
        lignes += f"""
        <div class="ligne-compte">
            <span>{escape ( username ) } — {labels.get ( status, status ) }</span>
            <form method="POST" style="display:inline;">
                {champ_csrf (  ) }
                <input type="hidden" name="username" value="{escape ( username ) }">
                <button type="submit" name="nouveau_statut" value="confiance" class="btn-accepter">⭐ Passer confiance</button>
                <button type="submit" name="nouveau_statut" value="connecte" class="btn-refuser">Retirer confiance</button>
            </form>
        </div>
        <div class="ligne-compte">
            <form method="POST" style="display:inline;">
                {champ_csrf (  ) }
                <input type="hidden" name="username" value="{escape ( username ) }">
                <input type="hidden" name="action" value="telephone">
                <label style="font-size:13px;">
                    <input type="checkbox" name="autorise" value="1" {coche} onchange="this.form.submit (  ) ">
                    📞 Autoriser à voir mon numéro de téléphone (Contact)
                </label>
            </form>
        </div>
        <div class="ligne-compte">
            <form method="POST" style="display:flex; gap:6px; align-items:center; width:100%;"
                  onsubmit="return confirm ( 'Supprimer définitivement le compte {escape ( username ) } ?' ) ;">
                {champ_csrf (  ) }
                <input type="hidden" name="username" value="{escape ( username ) }">
                <input type="text" name="motif" placeholder="Motif de la suppression" required
                       style="flex:4; width:auto; min-width:0; padding:8px; border-radius:6px; border:1px solid #aaa; font-size:14px;">
                <button type="submit" name="action" value="supprimer" class="btn-refuser" style="flex:0 0 auto; width:auto; padding:6px 10px; font-size:12px; white-space:nowrap;">🗑️ Supprimer</button>
            </form>
        </div>
        """
    if not comptes:
        lignes = "<p style='text-align:center;'>Aucun compte pour le moment.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/dev/contacts" class="btn-small">Messages contact</a>
        <a href="/dev/comptes-supprimes" class="btn-small">Comptes supprimés</a>
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Comptes</h2>
        {lignes}
    </div>
    """
    return page_html ( corps)


@app.route ( '/dev/comptes-supprimes')
@require_dev
def dev_comptes_supprimes (  ) :
    historique = lister_comptes_supprimes ( )
    lignes = ""
    for username, motif, date_suppression in historique:
        lignes += f"""
        <div class="ligne-contact">
            <strong>{escape ( username ) }</strong> — {escape ( date_suppression ) }<br>
            Motif : {escape ( motif ) }
        </div>
        """
    if not historique:
        lignes = "<p style='text-align:center;'>Aucun compte supprimé pour le moment.</p>"

    corps = f"""
    <div class="topbar">
        <a href="/dev/comptes" class="btn-small">Comptes</a>
        <a href="/" class="btn-small">Retour au site</a>
    </div>
    <div class="form-panel">
        <h2>Historique des comptes supprimés</h2>
        {lignes}
    </div>
    """
    return page_html ( corps)


# ---------------------------------------------------------------------------
# Arrêt normal / arrêt d'urgence / verrouillage
# ---------------------------------------------------------------------------

def est_confiance_ou_dev (  ) :
    """Renvoie (autorise, nom_a_afficher) : True si l'utilisateur est un compte
    confiance ou le développeur, avec un nom lisible pour les logs/motifs."""
    if session.get ( 'developer' ) :
        return True, "le développeur"
    utilisateur = session.get ( 'username')
    user = get_user ( utilisateur) if utilisateur else None
    if user and user[3] == 'confiance':
        return True, utilisateur
    return False, None


@app.route ( '/arret-normal', methods=['POST'])
def arret_normal (  ) :
    autorise, nom = est_confiance_ou_dev ( )
    if not autorise:
        return redirect ( url_for ( 'home' ) )
    horodatage = datetime.datetime.now (  ) .strftime ( '%d/%m/%Y %H:%M:%S')
    with open ( STOP_SOFT_FILE, 'w', encoding='utf-8') as f:
        f.write ( f"Arrêt normal demandé par {nom} le {horodatage}\n")
    return redirect ( url_for ( 'home' ) )


@app.route ( '/reinitialiser', methods=['POST'])
def reinitialiser (  ) :
    """Vide la console de logs affichée sur le site et annule une éventuelle
    pause (arrêt normal en attente ) . Ne supprime ni compte, ni script, ni rien
    d'autre — uniquement l'affichage de la console et la mise en pause."""
    autorise, nom = est_confiance_ou_dev ( )
    if not autorise:
        return redirect ( url_for ( 'home' ) )
    with open ( LOG_FILE, 'w', encoding='utf-8') as f:
        f.write ( "")
    if os.path.exists ( STOP_SOFT_FILE ) :
        os.remove ( STOP_SOFT_FILE)
    return redirect ( url_for ( 'home' ) )


@app.route ( '/emergency-stop', methods=['POST'])
def emergency_stop (  ) :
    autorise, nom = est_confiance_ou_dev ( )
    if not autorise:
        return redirect ( url_for ( 'home' ) )
    creer_verrouillage ( f"Arrêt d'urgence déclenché par {nom}")
    return redirect ( url_for ( 'home' ) )


@app.route ( '/dev/verrouiller', methods=['POST'])
@require_dev
def dev_verrouiller (  ) :
    raison = request.form.get ( 'raison', '' ) .strip ( )
    if not raison:
        raison = "Verrouillage manuel par le développeur"
    else:
        raison = f"Verrouillage manuel par le développeur — {raison}"
    creer_verrouillage ( raison)
    return redirect ( url_for ( 'home' ) )


@app.route ( '/dev/maintenance', methods=['POST'])
@require_dev
def dev_maintenance (  ) :
    if maintenance_active (  ) :
        desactiver_maintenance ( )
    else:
        activer_maintenance ( )
    return redirect ( url_for ( 'home' ) )


@app.route ( '/dev/feu', methods=['POST'])
@require_dev
def dev_feu (  ) :
    nouvelle_couleur = "rouge" if lire_feu ( ) == "vert" else "vert"
    definir_feu ( nouvelle_couleur)
    return redirect ( url_for ( 'home' ) )


@app.route ( '/unlock', methods=['POST'])
def unlock (  ) :
    password = request.form.get ( 'password', '')
    if password == DEVELOPER_PASSWORD:
        if os.path.exists ( GLOBAL_LOCK_FILE ) :
            os.remove ( GLOBAL_LOCK_FILE)
        session['developer'] = True
        return redirect ( url_for ( 'home' ) )
    return page_verrouillage ( erreur="Mot de passe incorrect.")


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

@app.route ( '/api/log')
def api_log (  ) :
    if not os.path.exists ( LOG_FILE ) :
        return {"log": "Aucun log pour le moment. Le bot n'a pas encore été lancé."}
    with open ( LOG_FILE, "r", encoding="utf-8") as f:
        contenu = f.read ( )
    lignes = contenu.strip (  ) .split ( "\n")
    dernieres_lignes = "\n".join ( lignes[-100:])
    return {"log": dernieres_lignes}


# ============================================================
# API POUR LE BOT DISCORD (KataBump)
# ============================================================

# ⚠️ Choisis une longue chaîne aléatoire secrète, et mets EXACTEMENT
# la même valeur côté bot Discord (variable API_SECRET dans app.py ) .
# Ne la partage avec personne.
DISCORD_BOT_API_SECRET = os.environ.get ( 'DISCORD_BOT_API_SECRET')


def _verifier_secret_api (  ) :
    """Vérifie l'en-tête X-Api-Secret envoyé par le bot Discord."""
    return request.headers.get ( "X-Api-Secret") == DISCORD_BOT_API_SECRET


@app.route ( '/api/discord/scripts', methods=['GET'])
def api_discord_scripts (  ) :
    if not _verifier_secret_api (  ) :
        return {"erreur": "non autorisé"}, 403

    feu_actuel = lire_feu ( )
    disponibles = lister_scripts ( actifs_seulement=True)
    scripts_json = [
        {
            "id": script_id,
            "nom": nom,
            "demande_parametre": bool ( demande_parametre ) ,
        }
        for script_id, nom, fichier, actif, demande_parametre in disponibles
    ]
    return {"feu": feu_actuel, "scripts": scripts_json}


@app.route ( '/api/discord/lancer', methods=['POST'])
@csrf.exempt
def api_discord_lancer (  ) :
    if not _verifier_secret_api (  ) :
        return {"erreur": "non autorisé"}, 403

    donnees = request.get_json ( silent=True) or {}
    discord_id = str ( donnees.get ( "discord_id", "" )  ) .strip ( )
    script_id = donnees.get ( "script_id")
    parametre = (donnees.get ( "parametre") or "" ) .strip ( ) or None

    # Le bot ne laisse déjà passer que les personnes autorisées côté
    # Discord, mais on revérifie ici côté site pour rester cohérent avec
    # la liste "discord_autorises" que tu gères sur /dev/discord.
    nom_discord = est_discord_autorise ( discord_id)
    if not nom_discord:
        return {"ok": False, "message": "Ce compte Discord n'est pas autorisé sur le site."}, 403

    if lire_feu ( ) == "rouge":
        return {"ok": False, "message": "🔴 Le feu est au rouge, aucun script ne peut être lancé pour le moment."}

    echeance_cooldown = lire_echeance_cooldown ( )
    if echeance_cooldown and time.time ( ) < echeance_cooldown:
        secondes_restantes = int ( echeance_cooldown - time.time (  ) ) + 1
        return {"ok": False, "message": f"⏳ Merci d'attendre encore {secondes_restantes} seconde ( s ) ."}

    script = get_script ( script_id)
    if not script or not script[3]:
        return {"ok": False, "message": "Script introuvable ou désactivé."}

    demande_parametre = script[4]
    if demande_parametre and not parametre:
        return {"ok": False, "message": "Ce script demande un paramètre (nom de page ) ."}

    nom_script = script[1]

    # Cas particulier : "Info page" est lancé de façon SYNCHRONE (on attend
    # qu'il se termine) pour pouvoir renvoyer directement son résultat dans
    # Discord, au lieu du simple "Script lancé !" des autres scripts qui
    # tournent en arrière-plan.
    if nom_script == "Info page":
        fichier = os.path.basename ( script[2])
        chemin = os.path.join ( BASE_DIR, fichier)
        if not fichier.endswith ( ".py") or not os.path.isfile ( chemin ) :
            return {"ok": False, "message": "Erreur : fichier introuvable sur le serveur."}
        enregistrer_lancement ( nom_discord, nom_script, fichier, origine="Discord")
        commande = ["python3", chemin]
        if parametre:
            commande.append ( parametre)
        try:
            resultat = subprocess.run(
                commande, cwd=BASE_DIR, capture_output=True, text=True, timeout=30
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "message": "⏱️ Le script a mis trop de temps à répondre."}

        sortie = (resultat.stdout or "" ) .strip ( )
        erreur = (resultat.stderr or "" ) .strip ( )
        if not sortie and erreur:
            sortie = "Erreur du script : " + erreur
        if not sortie:
            sortie = " ( aucune information retournée ) "
        # Discord limite les messages à 2000 caractères, on garde une marge.
        sortie = sortie[:1900]
        return {"ok": True, "message": sortie}

    ok = lancer_script(
        script[2], parametre,
        utilisateur_lanceur=nom_discord,
        nom_script=nom_script,
        origine="Discord"
    )
    message = f"{nom_script} lancé !" if ok else "Erreur : fichier introuvable sur le serveur."
    return {"ok": ok, "message": message}


if __name__ == '__main__':
    app.run ( )
