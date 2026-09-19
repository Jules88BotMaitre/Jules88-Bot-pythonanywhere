import requests
import re
import time
import datetime
import os

API_URL = "https://fr.vikidia.org/w/api.php"
S = requests.Session()

# ⚠️ Identifiants chargés depuis des variables d'environnement (utilise un
# mot de passe d'application, pas ton mot de passe principal —
# Préférences > Sécurité sur Vikidia).
# Avant de lancer le script, définis ces variables, par exemple :
#   export VIKIDIA_BOT_USERNAME="Jules88!!Bot"
#   export VIKIDIA_BOT_PASSWORD="motdepasseapplication"
USERNAME = os.environ.get("VIKIDIA_BOT_USERNAME")
PASSWORD = os.environ.get("VIKIDIA_BOT_PASSWORD")

if not USERNAME or not PASSWORD:
    raise SystemExit(
        "❌ Identifiants manquants : définis les variables d'environnement "
        "VIKIDIA_BOT_USERNAME et VIKIDIA_BOT_PASSWORD avant de lancer le script."
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "bot_log.txt")

# Mêmes fichiers que ceux utilisés par flask_app.py et les autres scripts —
# doivent être dans le même dossier
STOP_SOFT_FILE = os.path.join(BASE_DIR, "arret_normal.txt")
GLOBAL_LOCK_FILE = os.path.join(BASE_DIR, "site_verrouille.txt")
PDD_DERNIER_ID_FILE = os.path.join(BASE_DIR, "pdd_dernier_id.txt")
EN_COURS_FILE = os.path.join(BASE_DIR, "bot_en_cours.txt")

PAGE_ARRET_URGENCE = "Discussion utilisateur:Jules88!!Bot"
PAGE_UTILISATEUR = "Utilisateur:Jules88!!Bot"

# ⏸️ Limite de sécurité entre deux modifications (en secondes)
DELAI_ENTRE_EDITS = 2

# Une page est considérée comme vide uniquement si elle fait exactement
# 0 octet (aucun caractère, pas même un espace)
SEUIL_VIDE = 2

# Namespaces à ignorer complètement : Utilisateur (2) et Discussion
# utilisateur (3) — ça exclut d'office les brouillons, les pages
# utilisateur (PU) et les pages de discussion utilisateur (PDD)
NAMESPACES_IGNORES = {"2", "-1", "-2"}

BANDEAU = "{{SI|Page vide|Jules88!!Bot}}"


def log(message):
    """Affiche le message et l'ajoute au fichier de log (lu par la console du site)."""
    heure = datetime.datetime.now().strftime("%H:%M:%S")
    ligne = f"[{heure}] {message}"
    print(ligne)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(ligne + "\n")


# ---------------------------------------------------------------------------
# Vérifications d'arrêt (identiques aux autres scripts du site)
# ---------------------------------------------------------------------------

def site_verrouille():
    return os.path.exists(GLOBAL_LOCK_FILE)


def arret_normal_demande():
    if os.path.exists(STOP_SOFT_FILE):
        log("⏸️ Arrêt normal demandé. Arrêt propre du script.")
        os.remove(STOP_SOFT_FILE)
        return True
    return False


def creer_verrouillage(raison):
    horodatage = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    with open(GLOBAL_LOCK_FILE, 'w', encoding='utf-8') as f:
        f.write(f"{raison} — le {horodatage}\n")


def verifier_nouveau_message_pdd(csrf_token):
    """Vérifie si un nouveau message est apparu sur la page de discussion du bot.
    Si c'est le cas, le bot répond, verrouille le site entier, et renvoie True."""
    r = S.get(API_URL, params={
        "action": "query",
        "prop": "revisions",
        "rvprop": "ids|content|timestamp",
        "titles": PAGE_ARRET_URGENCE,
        "format": "json"
    })
    pages = r.json().get("query", {}).get("pages", {})
    page = list(pages.values())[0]
    if "revisions" not in page:
        return False

    revision = page["revisions"][0]
    revid_actuel = str(revision["revid"])
    contenu = revision["*"]
    basetimestamp = revision["timestamp"]

    dernier_id_connu = None
    if os.path.exists(PDD_DERNIER_ID_FILE):
        with open(PDD_DERNIER_ID_FILE, "r", encoding="utf-8") as f:
            dernier_id_connu = f.read().strip()

    if dernier_id_connu is None:
        with open(PDD_DERNIER_ID_FILE, "w", encoding="utf-8") as f:
            f.write(revid_actuel)
        return False

    if revid_actuel == dernier_id_connu:
        return False

    reponse = "\n:Message reçu. Arrêt automatique du robot en attendant qu'un développeur prenne connaissance de ce message. ~~~~"
    nouveau_contenu = contenu + reponse

    r_post = S.post(API_URL, data={
        "action": "edit",
        "title": PAGE_ARRET_URGENCE,
        "text": nouveau_contenu,
        "basetimestamp": basetimestamp,
        "bot": "1",
        "summary": "Bot : accusé de réception, arrêt automatique",
        "token": csrf_token,
        "format": "json"
    })

    # IMPORTANT : on enregistre l'ID de la révision APRÈS la réponse du bot
    # (pas avant), sinon le bot détecterait sa propre réponse comme un
    # nouveau message au prochain lancement, et boucler indéfiniment dessus.
    resultat_post = r_post.json()
    nouveau_revid = resultat_post.get("edit", {}).get("newrevid")
    with open(PDD_DERNIER_ID_FILE, "w", encoding="utf-8") as f:
        f.write(str(nouveau_revid) if nouveau_revid else revid_actuel)

    creer_verrouillage("Nouveau message détecté sur la page de discussion du bot")
    log("🛑 Nouveau message détecté sur la PDD. Site verrouillé, arrêt du script.")
    return True


def mettre_a_jour_statut_page(csrf_token, en_ligne):
    """Met à jour la section statut de la page utilisateur du bot sur Vikidia
    (entre les balises <!-- STATUT_DEBUT --> et <!-- STATUT_FIN -->)."""
    try:
        r = S.get(API_URL, params={
            "action": "query",
            "prop": "revisions",
            "rvprop": "content|timestamp",
            "titles": PAGE_UTILISATEUR,
            "format": "json"
        })
        pages = r.json().get("query", {}).get("pages", {})
        page = list(pages.values())[0]
        if "revisions" not in page:
            return

        revision = page["revisions"][0]
        contenu = revision["*"]
        basetimestamp = revision["timestamp"]

        nouveau_statut = "🟢 En ligne" if en_ligne else "⚫ Hors ligne"
        nouveau_contenu, nb_remplacements = re.subn(
            r"(<!-- STATUT_DEBUT -->)(.*?)(<!-- STATUT_FIN -->)",
            rf"\1\n{nouveau_statut}\n\3",
            contenu,
            flags=re.DOTALL
        )
        if nb_remplacements == 0:
            return

        S.post(API_URL, data={
            "action": "edit",
            "title": PAGE_UTILISATEUR,
            "text": nouveau_contenu,
            "basetimestamp": basetimestamp,
            "bot": "1",
            "minor": "1",
            "summary": "Bot : mise à jour du statut",
            "token": csrf_token,
            "format": "json"
        })
    except Exception as e:
        log(f"⚠️ Impossible de mettre à jour le statut sur la page utilisateur : {e}")


def se_connecter():
    r1 = S.get(API_URL, params={
        "action": "query", "meta": "tokens", "type": "login", "format": "json"
    })
    login_token = r1.json()['query']['tokens']['logintoken']

    r2 = S.post(API_URL, data={
        "action": "login",
        "lgname": USERNAME,
        "lgpassword": PASSWORD,
        "lgtoken": login_token,
        "format": "json"
    })
    result = r2.json()
    if result.get("login", {}).get("result") != "Success":
        log(f"❌ Échec de connexion : {result}")
        raise Exception(f"Échec de connexion : {result}")
    log("✅ Connexion au compte réussie.")


def get_csrf_token():
    r = S.get(API_URL, params={"action": "query", "meta": "tokens", "format": "json"})
    return r.json()['query']['tokens']['csrftoken']


# ---------------------------------------------------------------------------
# Recherche des pages vides
# ---------------------------------------------------------------------------

def appel_api(params, methode="GET", tentatives=3):
    """Effectue un appel à l'API avec une petite pause (pour ne pas
    surcharger le serveur) et une vraie gestion d'erreur : si la réponse
    n'est pas du JSON valide (page d'erreur, coupure réseau...), on réessaie
    quelques fois avant d'abandonner proprement avec un message clair."""
    for tentative in range(1, tentatives + 1):
        try:
            if methode == "GET":
                r = S.get(API_URL, params=params, timeout=30)
            else:
                r = S.post(API_URL, data=params, timeout=30)
            time.sleep(0.5)  # petite pause pour rester léger sur le serveur
            return r.json()
        except requests.exceptions.RequestException as e:
            log(f"⚠️ Erreur réseau (tentative {tentative}/{tentatives}) : {e}")
        except ValueError:
            # r.json() a échoué : la réponse n'était pas du JSON
            extrait = r.text[:200].replace("\n", " ") if 'r' in dir() else "?"
            log(f"⚠️ Réponse inattendue de l'API (tentative {tentative}/{tentatives}) : {extrait}")
        time.sleep(3)
    raise Exception(f"Échec de l'appel API après {tentatives} tentatives : {params.get('action')}/{params.get('list', params.get('meta', ''))}")


def obtenir_pages_vides_candidates():
    """Utilise la page spéciale « Pages courtes » (Special:Shortpages), qui
    liste déjà les pages du wiki triées de la plus courte à la plus longue —
    beaucoup plus rapide que de parcourir chaque page une par une.
    On s'arrête dès qu'on tombe sur une page de plus de 0 octet, puisque la
    liste est triée par taille croissante."""
    candidates = []
    qpoffset = 0
    while True:
        params = {
            "action": "query",
            "list": "querypage",
            "qppage": "Shortpages",
            "qplimit": "max",
            "qpoffset": str(qpoffset),
            "format": "json"
        }
        data = appel_api(params)
        resultats = data.get("query", {}).get("querypage", {}).get("results", [])
        if not resultats:
            break

        for resultat in resultats:
            valeur = int(resultat.get("value", 999))
            if valeur > SEUIL_VIDE:
                # La liste est triée par taille croissante : dès qu'on
                # dépasse le seuil, plus la peine de continuer.
                return candidates

            titre = resultat["title"]
            namespace = str(resultat.get("ns", 0))
            if namespace in NAMESPACES_IGNORES:
                continue
            candidates.append(titre)

        qpoffset += len(resultats)

    return candidates


def poser_bandeau_si_vide(titre, csrf_token):
    """Vérifie une dernière fois le contenu réel de la page avant de poser le
    bandeau (au cas où elle aurait été modifiée entre-temps), et ignore les
    pages qui ont déjà le bandeau."""
    r = S.get(API_URL, params={
        "action": "query",
        "prop": "revisions",
        "rvprop": "content|timestamp",
        "titles": titre,
        "format": "json"
    })
    pages = r.json().get("query", {}).get("pages", {})
    page = list(pages.values())[0]
    if "missing" in page or "revisions" not in page:
        log(f"⏭️  '{titre}' : page introuvable, ignorée.")
        return False

    revision = page["revisions"][0]
    contenu = revision["*"]
    basetimestamp = revision["timestamp"]

    if len(contenu) > SEUIL_VIDE:
        log(f"⏭️  '{titre}' : n'est plus vide (0 octet), ignorée.")
        return False

    if "{{SI" in contenu or "{{si" in contenu.lower():
        log(f"⏭️  '{titre}' : bandeau déjà présent, ignorée.")
        return False

    nouveau_contenu = BANDEAU + ("\n" + contenu.strip() if contenu.strip() else "")

    donnees_edit = {
        "action": "edit",
        "title": titre,
        "text": nouveau_contenu,
        "basetimestamp": basetimestamp,
        "bot": "1",
        "summary": "Bot : pose du bandeau de suppression immédiate (page vide)",
        "token": csrf_token,
        "format": "json"
    }

    r2 = S.post(API_URL, data=donnees_edit)
    resultat = r2.json()

    # Un filtre anti-abus de type "avertissement" (pas "interdiction") bloque
    # la première tentative et attend une confirmation : on renvoie alors
    # exactement la même édition une deuxième fois pour la valider.
    code_erreur = resultat.get("error", {}).get("code", "")
    if code_erreur == "abusefilter-warning":
        log(f"⚠️ '{titre}' : avertissement d'un filtre anti-abus, nouvelle tentative de confirmation...")
        r2 = S.post(API_URL, data=donnees_edit)
        resultat = r2.json()

    if "edit" in resultat and resultat["edit"].get("result") == "Success":
        log(f"✅ '{titre}' : bandeau posé.")
        return True
    else:
        log(f"❌ Échec sur '{titre}' : {resultat}")
        return False


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    log("🚀 Script « pages vides » lancé.")

    if site_verrouille():
        log("🔒 Le site est verrouillé (arrêt d'urgence actif). Script non lancé.")
        return

    with open(EN_COURS_FILE, 'w', encoding='utf-8') as f:
        f.write("en cours\n")

    csrf_token = None
    try:
        se_connecter()
        csrf_token = get_csrf_token()
        mettre_a_jour_statut_page(csrf_token, en_ligne=True)

        if site_verrouille():
            log("🔒 Le site est verrouillé (arrêt d'urgence actif). Script arrêté.")
            return

        if verifier_nouveau_message_pdd(csrf_token):
            return

        if arret_normal_demande():
            return

        log("🔍 Recherche des pages vides (hors brouillons, PU et PDD des utilisateurs)...")
        candidates = obtenir_pages_vides_candidates()
        log(f"🔍 {len(candidates)} page(s) potentiellement vide(s) trouvée(s).")

        pages_modifiees = 0
        for i, titre in enumerate(candidates):
            if site_verrouille():
                log("🔒 Verrouillage global détecté, arrêt immédiat du script.")
                return
            if verifier_nouveau_message_pdd(csrf_token):
                return
            if arret_normal_demande():
                return

            a_modifie = poser_bandeau_si_vide(titre, csrf_token)

            if a_modifie:
                pages_modifiees += 1
                if i < len(candidates) - 1:
                    log(f"⏳ Pause de {DELAI_ENTRE_EDITS} secondes avant la prochaine modification...")
                    time.sleep(DELAI_ENTRE_EDITS)

        log(f"🏁 Script terminé. {pages_modifiees} bandeau(x) posé(s).")
    except Exception as e:
        log(f"❌ Le script s'est arrêté à cause d'une erreur : {e}")
    finally:
        if csrf_token:
            mettre_a_jour_statut_page(csrf_token, en_ligne=False)
        if os.path.exists(EN_COURS_FILE):
            os.remove(EN_COURS_FILE)


if __name__ == "__main__":
    main()
