# Évaluation sur le corpus de test (regex + LLM)

## Détection des PII

Périmètre évalué : ADDRESS_FULL, DATE_OF_BIRTH, EMAIL, IBAN, JOB_TITLE, LICENSE_PLATE, LOCATION, NIR, ORG, PERSON, PHONE. Correspondance : même type et recouvrement.

| | Précision | Rappel | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| Global (recouvrement) | 96.3 % | 81.5 % | 88.3 % | 207 | 8 | 47 |
| Global (positions exactes) | 95.7 % | 70.5 % | 81.2 % | 179 | 8 | 75 |

### Par type

| Type | Précision | Rappel | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| ADDRESS_FULL | 100.0 % | 77.8 % | 87.5 % | 21 | 0 | 6 |
| DATE_OF_BIRTH | 100.0 % | 63.6 % | 77.8 % | 7 | 0 | 4 |
| EMAIL | 100.0 % | 100.0 % | 100.0 % | 12 | 0 | 0 |
| IBAN | 100.0 % | 100.0 % | 100.0 % | 4 | 0 | 0 |
| JOB_TITLE | 90.9 % | 55.6 % | 69.0 % | 10 | 1 | 8 |
| LICENSE_PLATE | 100.0 % | 100.0 % | 100.0 % | 4 | 0 | 0 |
| LOCATION | 94.4 % | 73.9 % | 82.9 % | 17 | 1 | 6 |
| NIR | 100.0 % | 100.0 % | 100.0 % | 5 | 0 | 0 |
| ORG | 90.0 % | 75.0 % | 81.8 % | 27 | 3 | 9 |
| PERSON | 96.1 % | 83.9 % | 89.6 % | 73 | 3 | 14 |
| PHONE | 100.0 % | 100.0 % | 100.0 % | 27 | 0 | 0 |

### Rappel par cercle (types du périmètre)

| Cercle | Trouvées | Total | Rappel |
|---|---|---|---|
| 1 | 142 | 162 | 87.7 % |
| 2 | 55 | 74 | 74.3 % |
| 3 | 10 | 18 | 55.6 % |

### Par longueur de document

| Longueur | Précision | Rappel | TP | FP | FN |
|---|---|---|---|---|---|
| court | 86.1 % | 86.1 % | 31 | 5 | 5 |
| long | 97.1 % | 77.3 % | 34 | 1 | 10 |
| moyen | 98.4 % | 83.6 % | 127 | 2 | 25 |
| tres_long | 100.0 % | 68.2 % | 15 | 0 | 7 |

### Documents sans PII (faux positifs)

0 document(s) sur 13 contiennent au moins un faux positif (0 au total).
Faux positifs imbriqués ignorés (convention de la grille) : 2.

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
