# Évaluation sur le corpus de test (regex + LLM)

## Détection des PII

Périmètre évalué : ADDRESS_FULL, DATE_OF_BIRTH, EMAIL, IBAN, JOB_TITLE, LICENSE_PLATE, LOCATION, NIR, ORG, PERSON, PHONE. Correspondance : même type et recouvrement.

| | Précision | Rappel | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| Global (recouvrement) | 96.7 % | 92.5 % | 94.6 % | 236 | 8 | 19 |
| Global (positions exactes) | 96.7 % | 91.4 % | 94.0 % | 233 | 8 | 22 |

### Par type

| Type | Précision | Rappel | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| ADDRESS_FULL | 100.0 % | 100.0 % | 100.0 % | 27 | 0 | 0 |
| DATE_OF_BIRTH | 100.0 % | 100.0 % | 100.0 % | 12 | 0 | 0 |
| EMAIL | 100.0 % | 100.0 % | 100.0 % | 12 | 0 | 0 |
| IBAN | 100.0 % | 100.0 % | 100.0 % | 4 | 0 | 0 |
| JOB_TITLE | 92.3 % | 66.7 % | 77.4 % | 12 | 1 | 6 |
| LICENSE_PLATE | 100.0 % | 100.0 % | 100.0 % | 4 | 0 | 0 |
| LOCATION | 91.3 % | 91.3 % | 91.3 % | 21 | 2 | 2 |
| NIR | 100.0 % | 100.0 % | 100.0 % | 5 | 0 | 0 |
| ORG | 94.1 % | 88.9 % | 91.4 % | 32 | 2 | 4 |
| PERSON | 96.4 % | 92.0 % | 94.1 % | 80 | 3 | 7 |
| PHONE | 100.0 % | 100.0 % | 100.0 % | 27 | 0 | 0 |

### Rappel par cercle (types du périmètre)

| Cercle | Trouvées | Total | Rappel |
|---|---|---|---|
| 1 | 155 | 162 | 95.7 % |
| 2 | 69 | 75 | 92.0 % |
| 3 | 12 | 18 | 66.7 % |

### Par longueur de document

| Longueur | Précision | Rappel | TP | FP | FN |
|---|---|---|---|---|---|
| court | 86.8 % | 91.7 % | 33 | 5 | 3 |
| long | 97.8 % | 97.8 % | 44 | 1 | 1 |
| moyen | 98.6 % | 90.8 % | 138 | 2 | 14 |
| tres_long | 100.0 % | 95.5 % | 21 | 0 | 1 |

### Documents sans PII (faux positifs)

0 document(s) sur 13 contiennent au moins un faux positif (0 au total).
Faux positifs imbriqués ignorés (convention de la grille) : 4.

## Filtre d'injection de prompt

- Documents d'attaque détectés : 17 / 17 (100.0 %)
- Faux positifs sur documents normaux : 0 / 51 (0.0 %)

| Famille d'attaque | Détectés | Total |
|---|---|---|
| breakout_balise | 2 | 2 |
| empoisonnement_schema | 2 | 2 |
| encodage_base64 | 1 | 1 |
| fausse_autorite_systeme | 1 | 1 |
| faux_exemple_inline | 1 | 1 |
| injection_bloc_code | 1 | 1 |
| injection_conditionnelle | 1 | 1 |
| injection_directe_en | 1 | 1 |
| injection_directe_fr | 2 | 2 |
| injection_multilingue | 1 | 1 |
| paraphrase_indirecte | 1 | 1 |
| re_role | 1 | 1 |
| surcharge_noyade | 1 | 1 |
| tentative_modification | 1 | 1 |

Non détectés : aucun
Faux positifs : aucun
