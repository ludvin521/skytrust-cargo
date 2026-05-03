# Rapport d'examen — PKI-ADV-11 : SkyTrust Cargo

**Étudiant·e** : Ludvin GATSE NYNSON

---

## Phase 1 — Déploiement de la hiérarchie Cargo

>  **Fichiers déposés dans `phase1/`**
> - FAIT : `cargo-root.pem` — certificat Root Cargo
> - FAIT : `cargo-issuing.pem` — certificat Issuing Cargo
> - FAIT : `verify.txt` — sortie `openssl verify` (résultat : OK)
> - FAIT : `cargo-root.crl` — CRL initiale Root Cargo
> - FAIT : `cargo-issuing.crl` — CRL initiale Issuing Cargo

### 1.1 Écarts lab ↔ production

#### Bloc A — Dérogations autorisées (fourni)

| #   | Hypothèse | Exigence CP | Attendu en production | Impact en lab |
| --- | --------- | ----------- | --------------------- | ------------- |
| A1  | Instance EJBCA unique (Root + Issuing coexistent) | CP Root §1 « Séparation d'instance : Root et Issuing sur deux instances techniques distinctes » | Deux instances séparées : Root offline air-gapped ; Issuing online 24/7 | Root exposée en continu ; compromission de l'host unique = compromission des deux niveaux |
| A2  | Résolution DNS `pki.cargo.skytrust.local` via localhost | CP Root §2 / CP Issuing §2 — URLs publiées `http://pki.cargo.skytrust.local/...` | DNS interne résolvable + reverse-proxy HTTP dédié | Relying parties hors poste de lab ne peuvent valider la chaîne |
| A3  | SoftHSM en lieu et place d'un HSM matériel | CP Root §5 / CP Issuing §5 « HSM matériel certifié FIPS 140-2 Level 3 » | HSM matériel certifié FIPS 140-2 L3 (Thales Luna, Utimaco) | Clé privée exposée dans le volume Docker en clair |
| A4  | Auto-activation du token crypto (Root incluse) | CP Root §5 « Activation du HSM Root : quorum M-of-N officers ; auto-activation interdite » | HSM Root activé uniquement lors des cérémonies (M-of-N officers) | Root exploitable par tout attaquant ayant accès au conteneur |

#### Bloc B — Écarts supplémentaires identifiés

| #   | Exigence CP (document + §) | Réalité en lab | Attendu en production | Impact / remarque |
| --- | -------------------------- | -------------- | --------------------- | ----------------- |
| B1  | CP Root §5 : dual-control Root — minimum 2 opérateurs + 1 témoin RSSI + 1 scribe, PV signé | Root CA créée par une seule personne sans cérémonie formelle ni PV | Cérémonie documentée avec quorum M-of-N, PV signé par tous les participants | Aucune preuve d'intégrité de la création de la Root ; non-répudiation impossible |
| B2  | CP Root §4 : CRL Root publiée annuellement (366j max) | CRL Root configurée avec période 24h (Next Update = J+1) | Période CRL Root = 366 jours conforme §4 | Écart de période — acceptable en lab pour faciliter les tests |
| B3  | CP Issuing §2 : OCSP Issuing disponible sur URL dédiée `http://pki.cargo.skytrust.local/ocsp` | OCSP disponible sur `http://localhost:8081/ejbca/publicweb/status/ocsp` | Répondeur OCSP exposé sur URL publique avec nom DNS dédié | Les certificats émis pointent vers une URL localhost non accessible depuis l'extérieur |
| B4  | CP Root §2 / CP Issuing §2 : CDP et AIA dans les certificats pointant vers les URLs de publication | Les certificats émis ne contiennent pas de CDP ni AIA configurés | CDP → `http://pki.cargo.skytrust.local/crl/...` et AIA → URL OCSP + CA Issuers dans chaque certificat | Sans CDP/AIA, les relying parties ne peuvent pas vérifier la révocation automatiquement |
| B5  | CP Issuing §3 : CN doit correspondre au FQDN de l'endpoint ; OU=Cargo, O=SkyTrust Aviation, C=FR obligatoires | DN émis : `CN=tracker-001.cargo.skytrust.local` sans OU ni O ni C (profil EMPTY utilisé) | DN complet : `CN=tracker-001.cargo.skytrust.local, OU=Cargo, O=SkyTrust Aviation, C=FR` | Non-conformité au nommage CP — identité incomplète dans les certificats end-entity |
| B6  | CP Issuing §6 : clé end-entity générée côté demandeur — CA ne voit jamais la clé privée | Clé générée côté demandeur (openssl genrsa)  — CEPENDANT profil ENDUSER utilisé au lieu de CP_Cargo_TLS | CP_Cargo_TLS devrait être le profil dédié configuré avec les bonnes extensions EKU, KU, CDP, AIA | Le profil ENDUSER générique ne garantit pas les extensions métier requises par la CP Issuing §7.2 |
| B7  | CP Root §7.1 : Basic Constraints Root avec pathLen interdisant profondeur au-delà de 2 niveaux | pathLen non configuré (EJBCA CLI ne supporte pas --pathlen) — Basic Constraints : CA:TRUE sans pathLen | Basic Constraints : critical, CA:TRUE, pathLen:1 | Un attaquant contrôlant la Root pourrait créer des Issuing CA supplémentaires non autorisées |
| B8  | CP Issuing §8 : intégrité des journaux par chaînage cryptographique (EJBCA IntegrityProtectedDevice) | Logs EJBCA non protégés en intégrité (configuration par défaut) | Activer `IntegrityProtectedDevice` dans EJBCA pour tous les audit logs | Les logs peuvent être altérés sans détection ; non-conformité RGS §8 |

### 1.2 Mapping CP → configuration EJBCA

| #   | Exigence CP (document + §) | Implémentation EJBCA | Preuve |
| --- | -------------------------- | -------------------- | ------ |
| 1   | CP Root §6 : RSA 4096 bits pour la Root | Crypto Token `Cargo-RootCA-Token` avec alias `cargoRootKey` RSA 4096 sur SoftHSM | `ejbca.sh cryptotoken listkeys` → `cargoRootKey RSA 4096` |
| 2   | CP Root §6 : SHA-256 avec RSA (`sha256WithRSAEncryption`) | Paramètre `-s SHA256WithRSA` lors de `ejbca.sh ca init` | `openssl x509 -in cargo-root.pem -noout` → `Signature Algorithm: sha256WithRSAEncryption` |
| 3   | CP Root §4 : durée de vie Root 20 ans | `-v 7300` (7300 jours = 20 ans) lors de `ca init` | `openssl x509` → `notBefore: May 3 2026`, `notAfter: Apr 28 2046` |
| 4   | CP Root §4 : durée de vie Issuing 10 ans maximum | `-v 3650` (3650 jours = 10 ans) lors de `ca init` Issuing | `openssl x509` → `notBefore: May 3 2026`, `notAfter: Apr 30 2036` |
| 5   | CP Issuing §6 : RSA 3072 bits minimum pour l'Issuing | Crypto Token `Cargo-IssuingCA-Token` avec alias `cargoIssuingKey2` RSA 3072 | `ejbca.sh cryptotoken listkeys` → `cargoIssuingKey2 RSA 3072` |
| 6   | CP Root §1 : architecture Root → Issuing → end-entity (2 niveaux) | Issuing CA créée avec `--signedby 1054481377` (ID de la Root CA) | `listcas` → Issuing `Signed by: 1054481377` ; `openssl verify` → `cargo-issuing.pem: OK` |
| 7   | CP Root §7.3 : CRL Root format X.509v2, signée SHA-256 | EJBCA génère automatiquement la CRL lors de `ca init` | `openssl crl -in cargo-root.crl -inform DER -text` → `Issuer: CN=SkyTrust Cargo Root CA` |
| 8   | CP Issuing §7.3 : CRL Issuing publiée au moins toutes les 24h | CRL Issuing configurée dans EJBCA avec période 24h | `openssl crl -in cargo-issuing.crl -inform DER` → `Next Update: +24h` |
| 9   | CP Issuing §4 : révocation avec motif `keyCompromise` publiée immédiatement | `ejbca.sh ra revokecert ... 1` (reason=1=keyCompromise) + `ca createcrl` | CRL après révocation contient serial `2EC4274E...` avec `Key Compromise` |
| 10  | CP Issuing §4 : OCSP temps réel — révocation visible immédiatement | Répondeur OCSP EJBCA natif sur `/ejbca/publicweb/status/ocsp` | `openssl ocsp` → tracker-002 `revoked, Reason: keyCompromise` immédiatement après révocation |

### 1.3 Remarques

La configuration a été réalisée intégralement en ligne de commande (CLI EJBCA + OpenSSL + Docker). Le profil `ROOTCA` EJBCA ne permettant pas de configurer `pathLen` via CLI dans cette version (9.3.7 CE), la contrainte de profondeur n'a pas pu être appliquée — écart documenté en B7. L'utilisation du profil ENDUSER générique au lieu du profil métier `CP_Cargo_TLS` est due à une incompatibilité de configuration du profil End Entity en lab (écart documenté en B5/B6).

---

## Phase 2 — Cycle de vie automatisé des certificats Cargo

>  **Fichiers déposés dans `phase2/`**
> - FAIT : `tracker-001.pem` — certificat tracker-001.cargo.skytrust.local
> - FAIT : `tracker-001.csr` — CSR tracker-001 (clé privée restée côté demandeur)
> - FAIT : `tracker-002.pem` — certificat tracker-002.cargo.skytrust.local (avant révocation)
> - FAIT : `cargo-issuing-postrevoke.crl` — CRL après révocation de tracker-002
> - FAIT : `ocsp-tracker-001.txt` — réponse OCSP tracker-001 (`good`)
> - FAIT : `ocsp-tracker-002.txt` — réponse OCSP tracker-002 (`revoked`)

### Éléments de configurations créés pour ce besoin

- **Certificate Profile** `CP_Cargo_TLS` : profil end-entity dédié aux endpoints Cargo TLS, basé sur ENDUSER, associé à la `SkyTrust Cargo Issuing CA`.
- **End Entity Profile** `EEP_Cargo_TLS` : profil end entity avec Default CA = Issuing Cargo, Default Certificate Profile = CP_Cargo_TLS, Token = User Generated.
- **End entities** créées via CLI : `tracker-001.cargo.skytrust.local` et `tracker-002.cargo.skytrust.local` avec token USERGENERATED (clé privée générée côté demandeur).
- **Émission via** `ejbca.sh createcert` avec CSR fournie en argument — la CA ne voit jamais la clé privée (conformité CP Issuing §6).

### Justifications clés

La clé privée de chaque tracker est générée localement (`openssl genrsa`) et ne transite jamais vers EJBCA, conformément à la CP Issuing §6. La révocation de tracker-002 avec motif `keyCompromise` (reason=1) a été réalisée via CLI et la CRL régénérée immédiatement, respectant le délai de publication CRL après compromission (CP Issuing §4). Le répondeur OCSP EJBCA natif permet une vérification en temps réel — tracker-002 passe à `revoked` immédiatement, tracker-001 reste `good`.

### Remarques

Le script `enroll-cargo.sh` fourni n'a pas pu être utilisé directement car la REST API nécessite une configuration d'authentification mTLS non disponible dans l'environnement de lab. L'émission a été réalisée via la CLI EJBCA (`ejbca.sh createcert`) qui produit le même résultat fonctionnel.

---

## Phase 3 — Intégrations métier

### Partie A — Portail de suivi cargo protégé par mTLS

>  **Fichiers déposés dans `phase3/partieA/`**
> - FAIT : `nginx.conf` — configuration nginx avec mTLS activé
> - FAIT : `serveur-cargo.pem` — certificat portal.cargo.skytrust.local
> - FAIT : `client-cargo.pem` — certificat partenaire.cargo.skytrust.local
> - FAIT : `test-ok.txt` — trace acceptation (certificat client Cargo valide) → HTTP 200
> - FAIT : `test-sans-cert.txt` — trace rejet (aucun certificat) → HTTP 400
> - FAIT : `test-autre-pki.txt` — trace rejet (certificat autre PKI) → HTTP 400

#### 3.A.1 Éléments de configurations de la PKI créés

- **Certificat serveur** `portal.cargo.skytrust.local` émis par `SkyTrust Cargo Issuing CA` (profil ENDUSER, RSA 3072, SAN DNS).
- **Certificat client** `partenaire.cargo.skytrust.local` émis par `SkyTrust Cargo Issuing CA` (profil ENDUSER, RSA 3072).
- **Configuration nginx** sur port 9443 (8443 occupé par EJBCA exam) avec `ssl_verify_client on` et `ssl_client_certificate` pointant vers la chaîne Issuing + Root Cargo.

#### 3.A.2 Justifications clés

Le mTLS est configuré avec `ssl_verify_client on` — nginx exige un certificat client valide signé par la chaîne Cargo. Les trois scénarios sont démontrés : accès autorisé avec certificat Cargo valide (HTTP 200 + CN affiché), refus sans certificat (HTTP 400 `No required SSL certificate was sent`), refus avec certificat d'une autre PKI (HTTP 400 `The SSL certificate error`). Le fichier `ssl_client_certificate` contient la chaîne complète Issuing + Root pour permettre la validation de tous les certificats émis par la PKI Cargo.

#### 3.A.3 Remarques

Le port utilisé est 9443 au lieu de 443 car le port 443 est occupé par l'instance EJBCA principale des labs (port 8443 mappé sur 443). Le port 8443 est occupé par l'instance EJBCA exam. Écart documenté et sans impact fonctionnel en lab.

---

### Partie B — Signature des manifestes cargo

>  **Fichiers déposés dans `phase3/partieB/`**
> - FAIT : `manifeste-signe.p7s` — signature CMS/CAdES du manifeste (format DER)
> - FAIT : `manifeste.tsq` — requête de timestamp SHA-256 (CAdES-T)
> - FAIT : `verify.txt` — trace vérification (`CMS Verification successful`)
> - FAIT : `manifeste-verifie.json` — contenu extrait après vérification
> - FAIT : `signataire.pem` — certificat du signataire

#### 3.B.1 Éléments de configurations de la PKI créés

- **Certificat signataire** `signataire.cargo.skytrust.local` émis par `SkyTrust Cargo Issuing CA` (profil ENDUSER, RSA 3072, usage signature).
- **Signature CMS** réalisée avec `openssl cms -sign` en SHA-256, format DER, mode `nodetach` (données incluses dans le fichier signé).
- **Requête timestamp** générée avec `openssl ts -query -sha256` pour constituer le composant T de CAdES-T.

#### 3.B.2 Éléments pour prouver la conformité de la signature

La vérification avec `openssl cms -verify -CAfile cargo-root.pem` retourne `CMS Verification successful` et restitue le manifeste original intact. La chaîne de confiance complète Root → Issuing → Signataire est vérifiée. Le fichier `manifeste-verifie.json` contient le manifeste CARGO-2026-04-21-SK741 identique à l'original, prouvant l'intégrité des données signées.

#### 3.B.3 Justifications clés

La signature CAdES-BES (CMS avec certificat embarqué) est réalisée avec SHA-256 conformément à la CP Issuing §6. La requête de timestamp (`manifeste.tsq`) constitue le composant -T de CAdES-T — en production, cette requête serait soumise à un TSA (Time Stamping Authority) qualifié pour obtenir un jeton de temps opposable. En lab, la requête est générée mais non soumise à un TSA externe (écart d'environnement). Les certificats émis sous cette CP supportent des signatures électroniques **avancées (AdES)** conformément à CP Issuing §9 — non qualifiées QES car l'Issuing n'est pas un QTSP.

#### 3.B.4 Remarques

Le niveau CAdES-T complet nécessiterait un TSA externe accessible (ex. `timestamp.digicert.com`). En lab isolé, la requête TSQ est générée (`manifeste.tsq`) mais le jeton de réponse TSR n'est pas disponible. Cet écart est documenté et sans impact sur la démonstration du mécanisme de signature.

---

## Phase 4 — Audit du dossier PKI de NordAir Technical

### 4.1 Rapport d'écart NordAir Technical

| #   | Localisation | Constat | Exigence / référence | Sévérité |
| --- | ------------- | ------- | -------------------- | -------- |
| 1   | Doc A + Doc B | Validité Issuing 38 ans (2026→2064) avec clé RSA-2048 | ANSSI RGS B1 : RSA-2048 non recommandé au-delà de 2030 — Issuing valable jusqu'en 2064 | **Critique** |
| 2   | Doc A + Doc C | Cérémonie Root avec un seul opérateur présent (Opérateur 2 absent, Témoin audit absent) | CP Cargo Root §5 : dual-control minimum 2 opérateurs + 1 témoin RSSI + 1 scribe | **Critique** |
| 3   | Doc C | Clé Issuing générée hors HSM via `openssl genrsa -out issuing.key 2048` sur serveur de signature | CP Cargo Root §5/§6 + CP Issuing §5 : clé dans HSM FIPS 140-2 L3 — ne sort jamais du périmètre HSM | **Critique** |
| 4   | Doc A + Doc C | Export PKCS#12 complet (clé privée + certificat + chaîne) avec mot de passe communiqué oralement | CP Cargo Issuing §5 : clé privée Issuing ne sort jamais du HSM — stockage PKCS#12 sur serveur = violation | **Critique** |
| 5   | Doc B | Key Usage Issuing inclut `Digital Signature` et `Key Encipherment` en plus de `Certificate Sign` et `CRL Sign` | CP Cargo Root §7.2 : Key Usage Issuing restreint aux seuls usages nécessaires à la fonction d'Issuing | **Majeur** |
| 6   | Doc B | Pas de contrainte `pathlen` sur le certificat Issuing (Basic Constraints : `CA:TRUE` sans pathlen:0) | CP Cargo Root §7.2 : Basic Constraints doit interdire toute émission de sous-intermédiaire (pathlen:0) | **Majeur** |
| 7   | Doc D | Conservation des journaux 2 ans glissants seulement (purge automatique à 730 jours) | CP Cargo §8 : conservation 6 ans minimum (exigence RGS) | **Majeur** |
| 8   | Doc A + Doc D | Administrateur PKI unique `khalvorsen` — toutes les opérations réalisées par une seule personne | CP Cargo Root §5 : dual-control opérationnel — toute révocation manuelle requiert validation d'un second opérateur | **Majeur** |
| 9   | Doc D + Doc A | Aucun mécanisme d'intégrité des journaux mentionné (note NordAir le confirme explicitement) | CP Cargo §8 : chaînage cryptographique ou signature d'entrée activés (EJBCA `IntegrityProtectedDevice`) | **Modéré** |

### 4.2 Justifications clés

Les écarts les plus critiques concernent la sécurité des clés privées : la clé Issuing est générée hors HSM et stockée en PKCS#12 avec mot de passe oral (écarts 3 et 4), ce qui annule complètement la protection apportée par le HSM Root. La cérémonie incomplète (écart 2) signifie qu'aucun contrôle indépendant n'a été exercé lors de la création de la Root CA. La validité de 38 ans avec RSA-2048 (écart 1) est particulièrement préoccupante car la clé sera cryptographiquement vulnérable bien avant l'expiration du certificat. L'absence de séparation des devoirs (écart 8) et d'intégrité des logs (écart 9) empêche toute détection d'actions frauduleuses de l'administrateur unique.

### 4.3 Remarques Phase 4

L'analyse se base sur les documents A à D fournis. Les écarts identifiés sont croisés entre plusieurs documents pour maximiser la pertinence. La référence principale utilisée est la CP Cargo SkyTrust que nous venons d'implémenter, complétée par les principes généraux RFC 3647 et RGS.
