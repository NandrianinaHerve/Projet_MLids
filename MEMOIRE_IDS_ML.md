# SYSTÈME DE DÉTECTION D’INTRUSION BASÉ SUR LE MACHINE LEARNING (IDS-ML)

## Page de garde

**Titre du mémoire**  
SYSTÈME DE DÉTECTION D’INTRUSION BASÉ SUR LE MACHINE LEARNING POUR LA SURVEILLANCE TEMPS RÉEL DU TRAFIC RÉSEAU

**Auteur**  
Nom Prénom (Étudiant)

**Établissement**  
Université Exemple  
Faculté des Sciences et Technologies  
Département d’Informatique

**Diplôme préparé**  
Mémoire de fin d’études présenté en vue de l’obtention du Diplôme de Master en Sécurité des Systèmes d’Information

**Encadrant**  
Dr. Nom Prénom, Maître de Conférences

**Année académique**  
2024 – 2025

---

## Remerciements

Je souhaite tout d’abord exprimer ma profonde gratitude à mon encadrant, Dr. Nom Prénom, pour son accompagnement, ses conseils méthodologiques et sa disponibilité tout au long de la réalisation de ce mémoire. Je le remercie particulièrement pour la confiance accordée à ce projet et pour la liberté laissée dans l’exploration de solutions techniques innovantes.

Je remercie également l’ensemble du corps enseignant du Département d’Informatique de l’Université Exemple pour la qualité des enseignements dispensés au cours de ces années de formation, qui ont constitué un socle solide pour la conduite de ce travail.

Je tiens à exprimer ma reconnaissance à mes collègues de promotion et amis, pour leurs échanges constructifs, leurs encouragements et leur soutien moral dans les périodes de doute. Je pense en particulier à [Noms des amis], avec qui j’ai partagé de nombreux moments d’apprentissage et de collaboration.

Je remercie enfin ma famille pour son soutien indéfectible, sa patience et ses encouragements constants. Sans leur appui, ce mémoire n’aurait pas pu voir le jour.

---

## Table des matières

1. [Introduction générale](#chapitre-1--introduction-générale)  
2. [État de l’art](#chapitre-2--état-de-lart)  
3. [Analyse et conception](#chapitre-3--analyse-et-conception)  
4. [Implémentation](#chapitre-4--implémentation)  
5. [Tests et résultats](#chapitre-5--tests-et-résultats)  
6. [Conclusion et perspectives](#chapitre-6--conclusion-et-perspectives)  
7. [Bibliographie](#bibliographie)  
8. [Annexes](#annexes)

---

## Liste des figures et tableaux

**Figures**  
Figure 1 – Schéma conceptuel d’un système de détection d’intrusion (IDS) dans un réseau d’entreprise (description textuelle).  
Figure 2 – Architecture globale du système IDS-ML développé (description textuelle).  
Figure 3 – Schéma textuel du diagramme de classes principal du système IDS-ML.  
Figure 4 – Description textuelle du diagramme de cas d’utilisation.  
Figure 5 – Description textuelle du diagramme de séquence de la détection d’une attaque.  
Figure 6 – Description textuelle du diagramme d’activité du processus de détection.  
Figure 7 – Description de la matrice de confusion du modèle Random Forest.  
Figure 8 – Description de l’interface web de supervision IDS-ML.

**Tableaux**  
Tableau 1 – Comparaison des principales catégories d’IDS (NIDS, HIDS, hybrides).  
Tableau 2 – Comparaison des méthodes de détection par signatures et par anomalies.  
Tableau 3 – Comparaison de quelques algorithmes de Machine Learning pour les IDS.  
Tableau 4 – Synthèse des besoins fonctionnels et non fonctionnels du système IDS-ML.  
Tableau 5 – Récapitulatif des 14 variables (features) utilisées par le modèle ML.  
Tableau 6 – Paramètres principaux de configuration du système IDS-ML.  
Tableau 7 – Performances expérimentales du modèle Random Forest (accuracy, précision, rappel, F1-score).  
Tableau 8 – Analyse du taux de faux positifs et faux négatifs.  
Tableau 9 – Comparaison qualitative entre IDS-ML et solutions existantes.

---

## Liste des abréviations

- **IDS** : Intrusion Detection System (Système de détection d’intrusion)  
- **NIDS** : Network-based Intrusion Detection System (IDS basé réseau)  
- **HIDS** : Host-based Intrusion Detection System (IDS basé hôte)  
- **ML** : Machine Learning (Apprentissage automatique)  
- **RF** : Random Forest  
- **AI** : Artificial Intelligence (Intelligence artificielle)  
- **TCP** : Transmission Control Protocol  
- **UDP** : User Datagram Protocol  
- **HTTP** : HyperText Transfer Protocol  
- **HTTPS** : HyperText Transfer Protocol Secure  
- **DNS** : Domain Name System  
- **API** : Application Programming Interface  
- **GUI** : Graphical User Interface  
- **CPU** : Central Processing Unit  
- **DoS** : Denial of Service  
- **DDoS** : Distributed Denial of Service  
- **SQL** : Structured Query Language  
- **UML** : Unified Modeling Language  
- **CSV** : Comma-Separated Values  
- **JSON** : JavaScript Object Notation  
- **TTL** : Time To Live  
- **IP** : Internet Protocol

---

## Résumé

La multiplication des attaques informatiques ciblant les infrastructures critiques, les entreprises et les particuliers impose la mise en place de mécanismes de surveillance continue des réseaux. Les systèmes de détection d’intrusion (IDS) constituent un élément fondamental de ces mécanismes en permettant l’identification précoce des comportements suspects et des tentatives d’intrusion. Toutefois, les IDS traditionnels basés sur des signatures atteignent leurs limites face à la diversité, à la sophistication et à la rapidité d’évolution des menaces contemporaines. Dans ce contexte, l’intégration de techniques de Machine Learning (ML) au sein des IDS apparaît comme une approche prometteuse pour améliorer la détection d’attaques inconnues et réduire les faux positifs.

Ce mémoire présente la conception et la réalisation d’un système de détection d’intrusion basé sur le Machine Learning (IDS-ML) appliqué à la surveillance temps réel des connexions réseau. Le système repose sur une architecture modulaire implémentée en Python et déployée via le framework web Flask. Il intègre un module de capture réseau temps réel fondé sur `netstat` et `psutil`, un module de prétraitement des données extrayant quatorze variables décrivant les connexions observées, un module d’apprentissage automatique utilisant un classificateur Random Forest, un module de détection assurant la corrélation et la génération d’alertes, ainsi qu’une interface web de supervision développée avec Tailwind CSS.

Le modèle Random Forest est entraîné sur des données synthétiques générées de manière à représenter un trafic mixte comportant environ 85 % de connexions légitimes et 15 % de connexions malveillantes, incluant notamment des scénarios de port scanning, d’attaques par déni de service distribué (DDoS) et d’exploitation de vulnérabilités. Le système intègre un ensemble de mécanismes visant à réduire les faux positifs, tels que la prise en compte de processus en liste blanche, un seuil de confiance ajustable (0,85 par défaut) et une fenêtre de déduplication des alertes.

Les résultats expérimentaux montrent que le modèle Random Forest atteint une accuracy globale satisfaisante et un bon équilibre entre précision et rappel, avec une capacité à distinguer les comportements normaux de plusieurs types d’attaques synthétiques. Le tableau de bord web permet en outre une visualisation en temps réel des connexions, des alertes et des sites non sécurisés détectés (trafic HTTP non chiffré). Ce travail met en évidence la pertinence des approches basées sur le Machine Learning pour renforcer les capacités de détection d’intrusion tout en soulignant les défis persistants liés à la qualité des données, à la généralisabilité des modèles et à l’intégration opérationnelle dans des environnements hétérogènes.

**Mots-clés** : Sécurité des réseaux, Système de détection d’intrusion, Machine Learning, Random Forest, Flask, Tailwind CSS, Surveillance temps réel.

---

## Abstract

The increasing number of cyberattacks targeting critical infrastructures, companies and individuals requires the deployment of continuous monitoring mechanisms for networked systems. Intrusion Detection Systems (IDS) are a cornerstone of such mechanisms as they enable early identification of suspicious behaviors and intrusion attempts. However, traditional signature-based IDS reach their limits when facing the diversity, sophistication and rapid evolution of modern threats. In this context, integrating Machine Learning (ML) techniques into IDS appears as a promising approach to improve the detection of unknown attacks and to reduce false positives.

This thesis presents the design and implementation of a Machine Learning-based Intrusion Detection System (IDS-ML) dedicated to real-time monitoring of network connections. The system relies on a modular architecture implemented in Python and deployed using the Flask web framework. It includes a real-time network capture module based on `netstat` and `psutil`, a data preprocessing module extracting fourteen features describing each observed connection, a Machine Learning module built on a Random Forest classifier, a detection module responsible for correlation and alert generation, and a web-based monitoring interface developed with Tailwind CSS.

The Random Forest model is trained on synthetic data generated to represent a mixed traffic composed of roughly 85% legitimate connections and 15% malicious ones, including port scanning scenarios, distributed denial of service (DDoS) attacks and vulnerability exploitation attempts. The system integrates several mechanisms aiming at reducing false positives, such as the consideration of whitelisted processes, an adjustable confidence threshold (0.85 by default) and an alert deduplication time window.

Experimental results show that the Random Forest model achieves a satisfactory overall accuracy and a good balance between precision and recall, with the ability to distinguish normal behaviors from several types of synthetic attacks. The web dashboard provides real-time visualization of connections, alerts and detected insecure sites (unencrypted HTTP traffic). This work highlights the relevance of Machine Learning-based approaches to strengthen intrusion detection capabilities, while underlining persistent challenges related to data quality, model generalization and operational integration into heterogeneous environments.

**Keywords**: Network security, Intrusion Detection System, Machine Learning, Random Forest, Flask, Tailwind CSS, Real-time monitoring.

---

## CHAPITRE 1 : INTRODUCTION GÉNÉRALE

### 1.1 Contexte et problématique de la cybersécurité

La transformation numérique généralisée des organisations, l’essor du télétravail, la prolifération des objets connectés et l’interconnexion croissante des systèmes d’information ont profondément modifié le paysage de la cybersécurité. Les réseaux d’entreprise ne sont plus des périmètres fermés et maîtrisés ; ils sont devenus des environnements distribués, hétérogènes et dynamiques, dans lesquels coexistent des postes de travail, des serveurs, des équipements mobiles, des services dans le cloud et des applications web exposées à Internet. Cette complexité accrue offre un terrain fertile aux acteurs malveillants, qu’il s’agisse de cybercriminels motivés par le gain financier, de groupes d’attaquants étatiques ou de hackers opportunistes exploitant des vulnérabilités connues.

Dans ce contexte, les intrusions réseau prennent des formes variées : scans de ports systématiques en vue d’identifier des services vulnérables, tentatives d’exploitation de failles logicielles, attaques par déni de service distribué visant à rendre indisponibles des ressources critiques, communications de commande et de contrôle entre des postes compromis et des serveurs distants, exfiltration discrète de données sensibles, etc. La rapidité d’exécution de ces attaques et la capacité des attaquants à masquer leur trafic dans un flux légitime rendent leur détection particulièrement difficile. Les solutions périmétriques classiques, telles que les pare-feux statiques ou les systèmes de filtrage basés uniquement sur des règles préconfigurées, se révèlent insuffisantes pour identifier des comportements anormaux subtils ou des menaces émergentes.

Les systèmes de détection d’intrusion (IDS) ont été conçus pour répondre à cette problématique en analysant le trafic réseau et/ou l’activité des hôtes afin de mettre en évidence des événements suspects pouvant signaler une attaque en cours ou imminente [1]. Les IDS traditionnels, largement déployés dans les infrastructures, s’appuient historiquement sur des bases de signatures décrivant des motifs connus de trafic malveillant (par exemple la chaîne d’octets caractéristique d’un exploit ou la séquence de paquets propre à un ver). Si cette approche est efficace pour reconnaître des attaques déjà répertoriées, elle présente deux limitations majeures : d’une part, l’impossibilité de détecter des attaques réellement nouvelles (zero-day) ou des variantes non encore signées ; d’autre part, la nécessité de maintenir en permanence à jour les bases de signatures, ce qui impose un effort considérable de veille et de déploiement.

Face à l’explosion du volume de données circulant sur les réseaux et à la sophistication croissante des menaces, la communauté scientifique et industrielle s’est tournée vers des approches de détection fondées sur l’analyse statistique et le Machine Learning. Ces approches visent à modéliser le comportement normal d’un système ou d’un réseau, puis à détecter les déviations significatives susceptibles de correspondre à des activités malveillantes. En exploitant les capacités d’apprentissage à partir de données, il devient possible de prendre en compte un grand nombre de variables descriptives, de capturer des relations non linéaires complexes et de s’adapter à l’évolution des usages. Cependant, l’intégration de ces techniques au sein d’IDS opérationnels reste un défi, notamment en raison des exigences de temps réel, des contraintes de ressources, de la rareté relative des exemples d’attaques dans les données, ainsi que de la nécessité de maintenir un taux de faux positifs acceptable pour les équipes de sécurité.

Le projet présenté dans ce mémoire s’inscrit précisément dans cette problématique : concevoir et implémenter un système de détection d’intrusion basé sur le Machine Learning, capable d’analyser en temps réel des connexions réseau observées sur une machine, de distinguer les comportements normaux des activités suspectes et de présenter les résultats de manière exploitable via une interface web de supervision.

### 1.2 Justification du choix du sujet

Le choix de travailler sur un IDS-ML se justifie par plusieurs arguments complémentaires. Tout d’abord, la cybersécurité constitue un domaine stratégique dans lequel les besoins en solutions innovantes sont considérables. Les incidents récents relatifs à des attaques massives par rançongiciels, à des compromissions de chaînes logistiques logicielles ou à des vols de données à grande échelle ont montré que même des organisations disposant d’outils de sécurité de pointe peuvent être prises en défaut lorsqu’elles ne disposent pas de capacités de détection suffisamment avancées [2]. Intégrer des techniques d’apprentissage automatique au sein de systèmes de détection contribue à améliorer la robustesse globale des dispositifs de défense en complétant les approches purement basées sur des signatures ou des règles expertes.

Ensuite, du point de vue académique, le sujet se situe à l’intersection de plusieurs disciplines : sécurité des réseaux, science des données, ingénierie logicielle et développement web. Il constitue ainsi un terrain propice pour mettre en pratique des connaissances théoriques variées : compréhension des protocoles réseaux (TCP, UDP, HTTP, HTTPS), maîtrise des concepts fondamentaux du Machine Learning (apprentissage supervisé, classification binaire, évaluation de modèles), application de bonnes pratiques de conception logicielle (architecture modulaire, séparation des responsabilités, utilisation de frameworks) et réalisation d’une interface web moderne et ergonomique. Cette transversalité confère au projet une valeur pédagogique importante.

Par ailleurs, le choix d’une implémentation s’appuyant sur Python, Flask et des bibliothèques de Machine Learning telles que scikit-learn répond à une volonté de proposer une solution reproductible, extensible et compatible avec des environnements de développement courants. Python est aujourd’hui un langage de référence pour la science des données et la cybersécurité ; de nombreux outils d’analyse, de capture et de traitement de trafic y sont disponibles. Flask permet de construire rapidement des API REST et des interfaces web légères, tandis que Tailwind CSS offre un cadre efficace pour composer des interfaces réactives et modernes. Le projet s’inscrit ainsi dans un écosystème technologique largement adopté, ce qui facilite sa réutilisation et ses évolutions.

Enfin, ce travail répond à une préoccupation pratique : disposer d’un outil d’observation temps réel du trafic réseau local, enrichi par une analyse intelligente basée sur un modèle d’apprentissage automatique, et présentant les informations de manière synthétique et exploitable. Le système IDS-ML développé vise à offrir une base expérimentale sur laquelle il sera possible d’explorer des variantes de modèles, d’augmenter la richesse des données collectées et d’étudier finement l’impact de différents paramètres (seuils, stratégies de prétraitement, politiques de déduplication d’alertes) sur les performances globales.

### 1.3 Objectifs du projet

Les objectifs du projet peuvent être déclinés en un objectif général et plusieurs objectifs spécifiques.

L’objectif général consiste à concevoir, implémenter et évaluer un système de détection d’intrusion basé sur le Machine Learning, capable de surveiller en temps réel le trafic réseau d’une machine, de classifier les connexions en normales ou suspectes, et de générer des alertes synthétiques consultables via une interface web.

Les objectifs spécifiques sont les suivants :

1. Étudier l’état de l’art des systèmes de détection d’intrusion et des approches de Machine Learning appliquées à la cybersécurité, en particulier les modèles de type Random Forest.  
2. Définir les besoins fonctionnels et non fonctionnels du système IDS-ML, en tenant compte des contraintes de temps réel, d’ergonomie de l’interface de supervision et de limitation des faux positifs.  
3. Concevoir une architecture logicielle modulaire comprenant un module de capture réseau, un module de prétraitement des données, un module d’apprentissage automatique, un module de corrélation et de génération d’alertes, ainsi qu’un front-end web.  
4. Implémenter le système en s’appuyant sur Python 3.x, Flask 2.3.3, scikit-learn 1.3.0 et un ensemble de bibliothèques complémentaires (numpy, pandas, psutil, joblib).  
5. Définir un protocole expérimental pour l’entraînement et l’évaluation du modèle de Machine Learning, incluant la génération de données synthétiques réalistes, la définition de métriques (accuracy, précision, rappel, F1-score) et l’analyse de la matrice de confusion.  
6. Analyser les résultats obtenus en termes de performances de détection, de taux de faux positifs et de comportement du système dans différents scénarios, et proposer des pistes d’amélioration et de prolongement du travail.

### 1.4 Méthodologie adoptée

La méthodologie adoptée pour mener à bien ce projet s’articule autour de plusieurs étapes successives, inspirées des démarches classiques de développement logiciel et de recherche expérimentale en informatique. Dans un premier temps, une phase de revue bibliographique a été réalisée afin de comprendre les fondements des systèmes de détection d’intrusion, de recenser les principaux types d’IDS (NIDS, HIDS, hybrides), de caractériser les méthodes de détection par signatures et par anomalies, et d’identifier les contributions majeures en matière d’IDS fondés sur le Machine Learning [3][4]. Cette phase a permis de dégager des critères de comparaison pertinents et de positionner le projet dans le paysage existant.

Une seconde phase a consisté en l’analyse et la spécification des besoins. À partir du contexte d’utilisation visé (surveillance d’une machine connectée à Internet), les exigences fonctionnelles ont été formalisées sous la forme de cas d’utilisation décrivant les interactions entre l’utilisateur, le système de capture, le module ML et l’interface web. Les besoins non fonctionnels (performance, scalabilité, lisibilité de l’interface, robustesse face aux erreurs, maintenabilité du code) ont également été identifiés. Cette étape s’est traduite par l’élaboration de modèles UML (diagramme de cas d’utilisation, diagramme de classes, diagrammes de séquence et d’activité) décrits textuellement dans le chapitre 3.

La troisième phase a porté sur la conception détaillée et l’implémentation. L’architecture modulaire du système a été définie en séparant clairement les responsabilités : capture réseau en temps réel via un composant dédié, prétraitement des données et extraction de features via un préprocesseur, apprentissage et prédiction via un classificateur Random Forest, détection et gestion d’alertes via un module spécialisé, exposition des fonctionnalités et visualisation des résultats via une application Flask et un tableau de bord en Tailwind CSS. Chaque module a été implémenté et testé de manière incrémentale, en veillant à respecter les interfaces définies lors de la phase de conception.

Enfin, une phase expérimentale a été menée pour entraîner le modèle de Machine Learning sur des données synthétiques réalistes, évaluer ses performances à l’aide de métriques standard, analyser la matrice de confusion, mesurer le taux de faux positifs et observer le comportement du système dans différents scénarios de trafic. Les résultats ont été interprétés de façon critique afin d’identifier les forces et les limites de l’approche proposée et de formuler des perspectives d’amélioration.

### 1.5 Organisation du document

Ce mémoire est structuré en six chapitres principaux, complétés par une bibliographie et plusieurs annexes techniques.

Le chapitre 1 présente le contexte général de la cybersécurité, la problématique des intrusions réseau, la justification du recours au Machine Learning pour la détection d’intrusion, les objectifs du projet, la méthodologie adoptée et l’organisation du document.

Le chapitre 2 est consacré à l’état de l’art. Il introduit les concepts fondamentaux des systèmes de détection d’intrusion, distingue les différentes catégories d’IDS (NIDS, HIDS, hybrides) et les approches de détection par signatures et par anomalies. Il présente également les principales familles d’algorithmes de Machine Learning applicables à la cybersécurité, en insistant sur le modèle Random Forest choisi pour ce projet, et décrit plusieurs travaux de recherche représentatifs sur les IDS basés sur ML. Enfin, il aborde brièvement les technologies web modernes utilisées pour l’interface de supervision.

Le chapitre 3 traite de l’analyse et de la conception du système IDS-ML. Il décrit les besoins fonctionnels et non fonctionnels, propose une architecture globale du système, détaille la conception du stockage des données, et présente les principaux diagrammes UML (cas d’utilisation, classes, séquences, activités) sous forme de descriptions textuelles.

Le chapitre 4 décrit l’implémentation du système. Il précise l’environnement de développement retenu, puis détaille successivement le module de capture réseau, le préprocesseur de données, le module de Machine Learning, le module de détection et l’interface web, en s’appuyant sur le code réellement implémenté dans les modules @ids_ml_system/network_capture.py, @ids_ml_system/preprocessor.py, @ids_ml_system/ml_model.py, @ids_ml_system/traffic_detector.py, @ids_ml_system/flask_app.py et @templates/index.html.

Le chapitre 5 présente la démarche de tests et d’évaluation. Il propose un plan de tests couvrant les modules individuels et les scénarios d’intégration, puis discute les résultats obtenus en termes de performances du modèle ML (accuracy, précision, rappel, F1-score), de matrice de confusion et d’analyse du taux de faux positifs. Il aborde également des aspects de performance opérationnelle tels que le temps de réponse et la charge générée par le système.

Enfin, le chapitre 6 conclut le mémoire en dressant un bilan du projet, en mettant en évidence les principales contributions, en discutant les difficultés rencontrées et en ouvrant sur des perspectives d’évolution, notamment l’intégration de techniques de Deep Learning (LSTM, CNN), l’utilisation d’outils de capture plus fins tels que Scapy, et la persistance des données d’alertes dans une base de données dédiée.

---

## CHAPITRE 2 : ÉTAT DE L’ART

### 2.1 Les Systèmes de Détection d’Intrusion (IDS)

#### 2.1.1 Définition et historique

Un système de détection d’intrusion (IDS) peut être défini comme un mécanisme logiciel ou matériel destiné à surveiller en continu un système d’information (réseau, hôtes, applications) afin d’identifier des activités non autorisées, des violations de politique de sécurité ou des comportements anormaux susceptibles de traduire une tentative d’intrusion [5]. Contrairement à un pare-feu, qui a pour vocation principale de filtrer le trafic entrant et sortant en fonction de règles prédéfinies, un IDS se concentre sur l’observation et l’analyse a posteriori des événements, avec pour objectif de générer des alertes lorsque des patterns suspects sont détectés.

Les premiers travaux sur les IDS remontent aux années 1980, avec notamment les travaux pionniers d’Anderson et de Denning, qui ont introduit la notion de profils de comportement normal des utilisateurs et des systèmes et proposé des approches statistiques pour détecter des anomalies [6]. Dans les années 1990, l’essor d’Internet et la multiplication des attaques réseau ont conduit au développement d’IDS commerciaux et open source, tels que Snort ou Bro (aujourd’hui Zeek), principalement basés sur des signatures élaborées manuellement par des experts de la sécurité. Ces solutions ont été largement déployées dans les réseaux d’entreprise et ont contribué à structurer la pratique de la détection d’intrusion.

Au fil du temps, les IDS se sont diversifiés, tant du point de vue de leur positionnement dans l’architecture (réseau vs hôte) que des techniques de détection employées (signatures, règles, anomalies, corrélation d’événements). Parallèlement, la montée en puissance des capacités de calcul et l’augmentation de la quantité de données collectées ont favorisé l’émergence d’approches de détection fondées sur le Machine Learning et l’intelligence artificielle. Ces nouvelles générations d’IDS cherchent à dépasser les limitations des systèmes à base de signatures en apprenant automatiquement à partir de grandes bases de données de trafic légitime et malveillant [7].

#### 2.1.2 Types d’IDS (NIDS, HIDS, Hybride)

Les IDS peuvent être classés en plusieurs catégories en fonction de leur positionnement et de leur périmètre d’observation. La distinction principale est généralement faite entre les systèmes basés réseau (NIDS) et les systèmes basés hôte (HIDS), auxquels s’ajoutent des architectures hybrides combinant les deux approches.

Un NIDS (Network-based IDS) est déployé au niveau du réseau, par exemple sur un segment stratégique ou en amont d’un pare-feu, et analyse le trafic circulant entre différentes machines. Il inspecte les paquets réseau (en-têtes, parfois charge utile) afin de détecter des patterns caractéristiques d’attaques. Le NIDS a l’avantage de fournir une vision globale du trafic et de pouvoir détecter des attaques visant plusieurs hôtes simultanément ; en revanche, il peut être rendu aveugle par le chiffrement généralisé des communications (HTTPS, VPN) ou par des techniques d’évasion avancées.

Un HIDS (Host-based IDS) est quant à lui installé directement sur un hôte (serveur, poste de travail) et surveille l’activité locale : fichiers, registres, processus, appels système, journaux d’événements, etc. Il peut ainsi détecter des comportements suspects propres à la machine (modification de fichiers système, exécution de binaires non autorisés, escalades de privilèges). Le HIDS bénéficie d’une visibilité fine mais limitée au périmètre de l’hôte sur lequel il est installé.

Les architectures hybrides combinent les apports des NIDS et des HIDS en agrégeant des informations collectées à différents niveaux (réseau, hôte, application) au sein d’une plateforme de corrélation, parfois intégrée dans un SIEM (Security Information and Event Management). Ce type d’architecture permet une meilleure contextualisation des événements et une détection plus robuste.

Le tableau suivant (Tableau 1) synthétise les principales caractéristiques de ces trois catégories.

**Tableau 1 – Comparaison des principales catégories d’IDS**

| Type d’IDS | Positionnement | Sources de données | Avantages principaux | Limites principales |
|-----------:|----------------|--------------------|----------------------|---------------------|
| NIDS       | Segment réseau, périmètre | Paquets réseau, flux, métadonnées | Vision globale du trafic, détection d’attaques distribuées | Impact du chiffrement, volumétrie élevée, risque d’évasion |
| HIDS       | Hôte (serveur, poste) | Journaux système, fichiers, processus, appels système | Visibilité fine sur l’hôte, détection d’actions locales | Périmètre limité, déploiement sur chaque machine |
| Hybride    | Plateforme centralisée | Événements NIDS + HIDS + autres sources | Corrélation multi-niveaux, meilleure contextualisation | Complexité de déploiement, coût de gestion et de corrélation |

Le système IDS-ML développé dans ce mémoire s’apparente à un HIDS enrichi de fonctionnalités réseau : il est exécuté localement sur une machine, observe les connexions réseau établies à partir de celle-ci, et corrèle ces observations avec des informations sur les processus locaux. Il emprunte ainsi des caractéristiques à la fois aux HIDS et aux NIDS.

#### 2.1.3 Méthodes de détection (signatures, anomalies)

Les IDS se distinguent également par les méthodes qu’ils utilisent pour identifier des comportements malveillants. Deux grandes familles de méthodes sont traditionnellement distinguées : la détection par signatures et la détection par anomalies.

La détection par signatures repose sur l’utilisation d’une base de connaissances contenant des descriptions explicites de patterns d’attaques connus : séquences de paquets, motifs de charge utile, combinaisons spécifiques de drapeaux TCP, etc. Lorsqu’un événement observé correspond à l’une de ces signatures, une alerte est générée. Cette approche présente l’avantage d’être très précise pour les attaques connues, avec un faible taux de faux positifs dès lors que les signatures sont bien définies. Cependant, elle est intrinsèquement incapable de détecter des attaques inédites ou des variantes non encore documentées (zero-day), et exige une mise à jour continue de la base de signatures.

La détection par anomalies consiste à modéliser un comportement normal (profil statistique d’un utilisateur, distribution des tailles de paquets, fréquence des connexions vers certains ports, etc.) et à considérer comme suspectes les déviations significatives par rapport à ce profil [6]. Cette approche est particulièrement adaptée pour détecter des attaques non connues à l’avance, mais elle souffre souvent d’un taux de faux positifs plus élevé, notamment lorsque le comportement normal évolue dans le temps ou présente une forte variabilité.

De nombreux IDS modernes combinent les deux approches : une composante à base de signatures détecte efficacement les attaques connues, tandis qu’une composante basée sur l’analyse de comportements et éventuellement sur le Machine Learning permet de repérer des anomalies plus subtiles. Le Tableau 2 résume les principales différences entre ces deux familles de méthodes.

**Tableau 2 – Comparaison détection par signatures vs détection par anomalies**

| Méthode                 | Principe | Forces | Faiblesses | Cas d’usage typiques |
|-------------------------|----------|--------|-----------|----------------------|
| Détection par signatures | Correspondance avec des patterns d’attaques connus | Faible taux de faux positifs pour les attaques connues ; interprétation facile | Incapacité à détecter des attaques nouvelles ; nécessité de mises à jour fréquentes | IDS classiques (Snort, Suricata), antivirus |
| Détection par anomalies  | Modélisation du comportement normal et détection des déviations | Capacité à détecter des attaques inconnues ; adaptation possible | Taux de faux positifs potentiellement élevé ; besoin de données représentatives | IDS basés sur ML, détection de fraudes, SIEM avancés |

Le système IDS-ML présenté dans ce mémoire s’inscrit dans une démarche de détection par anomalies fondée sur le Machine Learning : un modèle de classification est entraîné à distinguer le trafic normal du trafic malveillant, sur la base de quatorze variables extraites de chaque connexion. Toutefois, certains mécanismes simples proches de la détection par signatures sont également intégrés, comme la détection de trafic HTTP non chiffré ou l’utilisation d’une liste de ports considérés comme particulièrement sensibles.

### 2.2 Le Machine Learning en cybersécurité

#### 2.2.1 Algorithmes supervisés vs non supervisés

Le Machine Learning rassemble un ensemble de méthodes algorithmiques permettant à un système d’apprendre automatiquement à partir de données, sans être explicitement programmé pour chaque cas particulier [8]. En cybersécurité, ces méthodes sont utilisées pour détecter des intrusions, classifier des fichiers en malveillants ou légitimes, identifier du spam, repérer des comportements frauduleux, etc. On distingue classiquement plusieurs paradigmes d’apprentissage : supervisé, non supervisé, semi-supervisé et par renforcement.

Dans le cadre de la détection d’intrusion, l’apprentissage supervisé consiste à entraîner un modèle à partir d’un ensemble d’exemples de trafic pour lesquels la classe (normal ou attaque) est connue. Chaque exemple est représenté par un vecteur de variables caractéristiques (features), et le modèle apprend une fonction de décision qui associe à chaque vecteur une étiquette. Des algorithmes supervisés classiques pour ce type de tâche incluent la régression logistique, les k-plus proches voisins (k-NN), les perceptrons multicouches (MLP), les machines à vecteurs de support (SVM) et les méthodes d’ensembles comme les Random Forest ou les Gradient Boosting Machines [9]. Lorsqu’un jeu de données labellisé est disponible, l’apprentissage supervisé permet en général d’obtenir de bonnes performances de classification.

L’apprentissage non supervisé, à l’inverse, ne dispose pas d’étiquettes indiquant la nature des exemples. Le modèle cherche alors à découvrir la structure intrinsèque des données, par exemple en regroupant les observations en clusters (k-means, DBSCAN) ou en apprenant une représentation compacte (autoencodeurs). En détection d’intrusion, ces méthodes sont souvent utilisées pour l’analyse d’anomalies : l’idée est de modéliser le « nuage » de points correspondant au trafic normal et de considérer comme suspects les points qui en sont éloignés. L’apprentissage non supervisé est particulièrement intéressant lorsque l’on ne dispose que de peu d’exemples labellisés d’attaques, mais il peut être plus difficile à contrôler et à évaluer.

Le projet IDS-ML décrit dans ce mémoire adopte un paradigme supervisé : même si les données d’entraînement sont générées de manière synthétique, chaque exemple est explicitement annoté comme représentant un trafic normal ou malveillant. Le modèle appris est ensuite utilisé pour prédire la classe de nouvelles connexions observées en temps réel.

#### 2.2.2 Random Forest : principes et avantages

Random Forest est une méthode d’ensemble supervisée proposée par Breiman [10], qui consiste à combiner un grand nombre d’arbres de décision entraînés sur des sous-échantillons aléatoires des données et des variables. Chaque arbre prend une décision de classification, et la prédiction finale est obtenue par vote majoritaire (pour la classification) ou moyennage (pour la régression). L’algorithme introduit deux formes de randomisation : le bootstrap des exemples (chaque arbre est entraîné sur un échantillon tiré avec remise) et la sélection aléatoire d’un sous-ensemble de variables à chaque nœud.

Les principaux avantages de Random Forest dans le contexte de la détection d’intrusion sont les suivants :

- Capacité à modéliser des relations non linéaires complexes entre les variables, sans nécessiter de transformations manuelles sophistiquées.  
- Robustesse aux données bruitées et à la présence de variables peu informatives, grâce à l’agrégation des décisions de nombreux arbres.  
- Tolérance relative aux corrélations entre variables et à la présence de valeurs manquantes, dans certaines limites.  
- Possibilité d’estimer l’importance relative des variables (feature importance), ce qui facilite l’analyse du comportement du modèle et la compréhension des facteurs expliquant les décisions.  
- Facilité d’usage grâce à des implémentations robustes dans des bibliothèques comme scikit-learn, avec un nombre raisonnable d’hyperparamètres à régler.

Dans le système IDS-ML, le modèle Random Forest est paramétré avec un nombre d’estimateurs `n_estimators=100`, une profondeur maximale `max_depth=20`, un nombre minimal d’exemples pour scinder un nœud `min_samples_split=5` et un nombre minimal d’exemples par feuille `min_samples_leaf=2`. Ces valeurs constituent un compromis entre capacité de modélisation et risque de surapprentissage, en tenant compte de la taille modérée du jeu de données d’entraînement (quelques milliers d’exemples synthétiques) et de la nécessité de prédictions rapides en temps réel.

#### 2.2.3 État de l’art des IDS basés sur ML

De nombreux travaux académiques ont exploré l’application du Machine Learning à la détection d’intrusion, en particulier à partir de jeux de données de référence tels que KDD’99, NSL-KDD, UNSW-NB15 ou CICIDS2017 [11][12]. Ces jeux de données fournissent des enregistrements de trafic annotés contenant des attaques de différentes natures (DoS, probe, R2L, U2R, etc.) et sont couramment utilisés pour évaluer et comparer des modèles.

Les premières approches se sont appuyées sur des algorithmes classiques de classification supervisée, par exemple les réseaux de neurones multilayers, les SVM ou les arbres de décision. Des études comparatives ont mis en évidence que les méthodes d’ensembles comme Random Forest ou Gradient Boosting offrent souvent un bon compromis entre performance, robustesse et temps d’apprentissage [13]. Parallèlement, des approches non supervisées ont été proposées, utilisant par exemple le clustering ou l’analyse de densité pour détecter des anomalies dans le trafic.

Plus récemment, l’essor du Deep Learning a conduit à l’exploration de modèles plus complexes tels que les réseaux de neurones convolutionnels (CNN) appliqués à des représentations matricielles du trafic, ou les réseaux récurrents (LSTM, GRU) capturant la dimension temporelle des séquences de paquets [14]. Ces modèles peuvent offrir des performances supérieures sur des jeux de données massifs, mais leur coût de calcul, leur complexité de mise en œuvre et leur manque de transparence peuvent constituer des obstacles à leur adoption dans des contextes opérationnels.

Le système IDS-ML présenté ici s’inscrit dans une approche pragmatique : plutôt que de viser la performance absolue sur un jeu de données benchmark, il cherche à démontrer la faisabilité d’une intégration cohérente d’un modèle de Machine Learning au sein d’un système de surveillance temps réel, en utilisant un algorithme robuste et bien maîtrisé comme Random Forest. Cette approche facilite l’analyse du comportement du système, la maîtrise des ressources et l’extension progressive vers des modèles plus sophistiqués.

### 2.3 Technologies web modernes

#### 2.3.1 Architecture Flask

Flask est un micro-framework web Python léger, extensible et largement utilisé pour la construction d’API REST, de services web et d’applications de petite à moyenne taille. Contrairement à des frameworks plus complets comme Django, Flask se concentre sur un noyau minimal (gestion des routes, système de templates, gestion basique des requêtes et réponses) et s’appuie sur un écosystème d’extensions pour les fonctionnalités additionnelles (authentification, ORM, etc.) [15]. Cette philosophie « micro » en fait un choix naturel pour des projets expérimentaux ou des prototypes, ainsi que pour des services composant des architectures microservices.

Dans le cadre du système IDS-ML, Flask est utilisé pour exposer plusieurs routes HTTP : une route principale `/` qui sert la page HTML de l’interface de supervision (template `index.html` dans le dossier @templates/index.html), et plusieurs routes d’API sous le préfixe `/api/` permettant à l’interface JavaScript de récupérer les données de monitoring et de piloter le système. Le module principal @ids_ml_system/flask_app.py encapsule l’application Flask dans une classe `IDSFlaskApp`, ce qui permet de regrouper dans un même objet l’initialisation des composants (classificateur ML, capture réseau, détecteur) et la définition des routes.

L’architecture logique peut être décrite textuellement comme suit (Figure 2) : un composant central `IDSFlaskApp` instancie et relie trois sous-composants principaux : `MLTrafficClassifier` pour la partie Machine Learning, `RealNetworkCapture` pour la capture réseau, et `MLTrafficDetector` pour l’analyse temps réel et la génération d’alertes. L’application Flask expose des endpoints REST qui interrogent ces composants pour obtenir des statistiques (`/api/stats`), des journaux console (`/api/console_logs`), des journaux de trafic (`/api/traffic_logs`), des alertes (`/api/alerts`, `/api/alert_logs`), la liste des sites non sécurisés (`/api/insecure_sites`) et qui permettent de contrôler le système (`/api/control/start_capture`, `/stop_capture`, `/start_detection`, `/stop_detection`, `/train_model`, `/clear_logs`).

Cette architecture découple clairement la logique métier (capture, ML, détection) de la couche de présentation web, ce qui améliore la maintenabilité et la testabilité du système.

#### 2.3.2 Tailwind CSS pour les interfaces

Tailwind CSS est un framework CSS utilitaire qui fournit un ensemble de classes prédéfinies directement utilisables dans le HTML pour composer des interfaces modernes, réactives et cohérentes, sans recourir à des feuilles de styles personnalisées complexes. Plutôt que d’imposer des composants préfabriqués, Tailwind met à disposition des primitives de mise en forme (marges, couleurs, typographie, flexbox, grid, etc.) qui peuvent être combinées pour construire des designs variés [16].

Dans l’interface web de l’IDS-ML, le fichier @templates/index.html s’appuie sur Tailwind CSS via un chargement depuis un CDN (`https://cdn.tailwindcss.com`). Les différentes sections de la page (en-tête, boutons de contrôle, cartes de statistiques, console, liste de trafic, liste d’alertes, liste de sites non sécurisés) sont composées à l’aide de classes utilitaires Tailwind telles que `bg-white`, `rounded-lg`, `shadow-md`, `grid`, `text-gray-800`, etc. Cette approche permet de construire un tableau de bord lisible et moderne avec un code HTML relativement concis.

Les interactions dynamiques (mise à jour des statistiques, des logs, des alertes, déclenchement des actions de contrôle) sont gérées côté client en JavaScript, en utilisant l’API `fetch` pour interroger les endpoints Flask toutes les deux secondes (polling). Les fonctions JavaScript `updateStats`, `updateConsole`, `updateAlerts`, `updateInsecureSites` manipulent le DOM pour refléter en temps réel l’état du système. Des notifications visuelles sont également implémentées pour informer l’utilisateur du démarrage ou de l’arrêt de la capture, de la détection ou de l’entraînement du modèle.

### 2.4 Analyse comparative des solutions existantes

De nombreuses solutions de détection d’intrusion sont aujourd’hui disponibles, qu’il s’agisse de projets open source comme Snort, Suricata ou Zeek, de produits commerciaux intégrés à des pare-feux de nouvelle génération (NGFW), ou de services cloud de type IDS-as-a-Service [17]. Ces solutions se distinguent par leur périmètre (réseau, hôte, application), leurs capacités de traitement (débit supporté, support du chiffrement), les techniques de détection utilisées (signatures, règles, analyse comportementale, ML) et leur degré d’intégration avec d’autres composants de sécurité (SIEM, SOAR).

Le système IDS-ML développé dans ce mémoire ne prétend pas se substituer à ces solutions industrielles ; il constitue plutôt un démonstrateur pédagogique et expérimental. Toutefois, il est utile de situer ses caractéristiques par rapport à quelques approches représentatives, comme le synthétise le Tableau 3.

**Tableau 3 – Comparaison qualitative entre IDS-ML et quelques solutions existantes**

| Solution | Type | Méthode de détection principale | Support ML | Interface de supervision | Commentaire |
|---------|------|----------------------------------|-----------|-------------------------|------------|
| Snort / Suricata | NIDS | Signatures, règles | Limité (extensions possibles) | Interfaces externes, SIEM | Référence industrielle pour la détection par signatures sur trafic réseau. |
| Zeek (Bro) | NIDS | Analyse de protocoles, scripts | Possible via scripts et exports | Tableaux de bord externes | Forte capacité d’analyse sémantique des protocoles, extensible via scripts. |
| OSSEC / Wazuh | HIDS | Journaux, intégrité fichiers, règles | Intégration possible | Interfaces web dédiées | Orientation HIDS avec corrélation d’événements système. |
| IDS-ML (ce projet) | HIDS enrichi réseau | ML supervisé (Random Forest), règles simples | Oui (Random Forest intégré) | Tableau de bord web Tailwind CSS | Démonstrateur pédagogique, capture locale, génération de données synthétiques, interface unifiée. |

L’originalité principale d’IDS-ML réside dans son intégration étroite d’un module de Machine Learning, d’un module de capture locale (basé sur `netstat` et `psutil`) et d’une interface web en temps réel reposant sur Flask et Tailwind CSS. Alors que les solutions industrielles privilégient souvent la détection à haute performance sur de grands volumes de trafic, IDS-ML met l’accent sur la compréhension de bout en bout de la chaîne de traitement, depuis la collecte brute des connexions jusqu’à la visualisation des alertes.

---

## CHAPITRE 3 : ANALYSE ET CONCEPTION

### 3.1 Analyse des besoins fonctionnels et non-fonctionnels

Du point de vue fonctionnel, le système IDS-ML doit permettre à un utilisateur d’initier et d’arrêter la capture du trafic réseau local, d’activer ou de désactiver la détection basée sur le Machine Learning, d’entraîner le modèle à la demande, de consulter en temps réel les statistiques globales de trafic et de détection, de visualiser les alertes générées ainsi que la liste des connexions considérées comme non sécurisées (notamment le trafic HTTP non chiffré), et enfin de réinitialiser les journaux et les alertes via une action dédiée. Ces besoins sont traduits dans l’application web par la présence de boutons de contrôle (Capture, Arrêter, Détection ML, Arrêter ML, Entraîner ML, Effacer) et de panneaux d’affichage (console, trafic, alertes, sites non sécurisés, tuiles de statistiques).

Les besoins non fonctionnels couvrent plusieurs dimensions. En premier lieu, la réactivité : le système doit être capable d’actualiser les informations visibles sur l’interface toutes les deux secondes sans provoquer de latence excessive ni saturer les ressources de la machine. Cette contrainte impose une capture et un traitement légers, ainsi qu’une communication efficace entre le back-end Flask et le front-end JavaScript. En second lieu, la fiabilité : le système doit être robuste face aux erreurs ponctuelles (par exemple l’échec d’une commande `netstat` ou une exception lors du prétraitement d’une connexion) et doit les consigner dans les journaux sans interrompre globalement le fonctionnement.

La question des faux positifs est également centrale : déclencher des alertes à chaque connexion légèrement atypique conduirait rapidement à une surcharge d’informations pour l’opérateur et à une perte de confiance dans le système. IDS-ML intègre plusieurs mécanismes pour limiter ce phénomène : prise en compte de processus en liste blanche (`WHITELIST_PROCESSES` dans @ids_ml_system/config.py), détection spécifique du trafic lié aux navigateurs vers des ports courants (80, 443) comme étant légitime, utilisation d’un seuil de confiance `ML_CONFIDENCE_THRESHOLD` fixé à 0,85 pour considérer une prédiction comme pertinente, et mécanisme de déduplication d’alertes basé sur une fenêtre temporelle de 300 secondes (`ALERT_DEDUPLICATION_WINDOW`). Enfin, un plafond sur le nombre d’alertes par minute (`MAX_ALERTS_PER_MINUTE = 10`) limite la production d’alertes en cas de scénario très bruyant.

Le Tableau 4 synthétise les principaux besoins identifiés.

**Tableau 4 – Synthèse des besoins fonctionnels et non fonctionnels**

| Catégorie | Besoin | Description |
|-----------|--------|-------------|
| Fonctionnel | Capture réseau | Démarrer et arrêter la capture des connexions réseau locales. |
| Fonctionnel | Détection ML | Activer et désactiver la détection d’intrusion basée sur le modèle Random Forest. |
| Fonctionnel | Entraînement | Entraîner le modèle ML à la demande et afficher son accuracy. |
| Fonctionnel | Visualisation trafic | Afficher en temps réel les connexions observées, leur niveau de risque et leur caractère sécurisé ou non. |
| Fonctionnel | Alertes | Générer, stocker et afficher les alertes de sécurité avec leur sévérité. |
| Fonctionnel | Journaux | Afficher une console des événements système et des logs de trafic. |
| Fonctionnel | Nettoyage | Effacer les journaux et les alertes sur demande. |
| Non fonctionnel | Temps réel | Rafraîchir les données toutes les 2 secondes avec une latence acceptable. |
| Non fonctionnel | Robustesse | Gérer les erreurs sans interruption du système. |
| Non fonctionnel | Faux positifs | Réduire le taux de faux positifs via listes blanches, seuils, déduplication. |
| Non fonctionnel | Ergonomie | Fournir une interface claire, lisible, responsive. |

### 3.2 Architecture globale du système

L’architecture globale d’IDS-ML peut être décrite comme un ensemble de composants interconnectés organisés autour d’un noyau applicatif Python. La Figure 2 (description textuelle) illustre cette architecture logique.

**Figure 2 – Description textuelle de l’architecture globale d’IDS-ML**  
Au centre du schéma se trouve un bloc représentant le « Cœur IDS-ML » implémenté en Python. Ce bloc contient trois sous-composants principaux : (1) un composant « Capture réseau » correspondant à la classe `RealNetworkCapture` du module @ids_ml_system/network_capture.py ; (2) un composant « Classificateur ML » correspondant à la classe `MLTrafficClassifier` du module @ids_ml_system/ml_model.py ; (3) un composant « Détecteur ML » correspondant à la classe `MLTrafficDetector` du module @ids_ml_system/traffic_detector.py. Ces trois sous-composants sont alimentés en configuration et journaux par un module transversal `config` et `logger`.

Le composant « Capture réseau » se connecte à la couche système de la machine via les commandes `netstat` et la bibliothèque `psutil`, représentées dans la figure par un lien vers la « Pile réseau du système d’exploitation ». Il alimente un tampon interne de connexions observées, ainsi que des journaux de trafic. Ce flux est ensuite consommé par le composant « Détecteur ML », qui interroge régulièrement la liste des derniers paquets via la méthode `get_recent_packets`.

Le composant « Classificateur ML » fournit des services de prédiction (`predict`) et expose des informations sur l’état du modèle (`get_model_info`). Il est sollicité par le composant « Détecteur ML » pour obtenir, pour chaque paquet à analyser, une prédiction (NORMAL ou ATTACK) ainsi qu’une confiance et une probabilité d’attaque. Il offre également une méthode `train_model` permettant d’entraîner ou de réentraîner le modèle, et une méthode `load_model` pour charger un modèle précédemment sauvegardé via `joblib`.

Le composant « Détecteur ML » combine ces informations et applique une logique métier pour décider de la génération d’alertes : prise en compte du seuil de confiance, classification du type d’attaque, calcul de la sévérité, déduplication et limitation du nombre d’alertes par minute. Les alertes sont stockées dans une structure `deque` et également envoyées au module `Logger` pour être consultables par l’interface.

Enfin, l’ensemble de ces composants est encapsulé dans une application Flask (classe `IDSFlaskApp` dans @ids_ml_system/flask_app.py) qui expose des endpoints REST consommés par l’interface web. La figure montre ainsi un bloc « Interface web (Tailwind CSS + JavaScript) » communiquant avec l’application Flask via des requêtes HTTP `fetch` régulières, et affichant les informations dans un tableau de bord.

#### 3.2.1 Diagramme de classes (description textuelle)

Le diagramme de classes principal du système IDS-ML peut être décrit textuellement comme suit (Figure 3).

**Figure 3 – Description textuelle du diagramme de classes**  
La classe `IDSFlaskApp` contient les attributs `app: Flask`, `ml_classifier: MLTrafficClassifier`, `traffic_collector: RealNetworkCapture`, `detector: MLTrafficDetector`. Elle fournit les méthodes `__init__`, `setup_components`, `setup_routes` et `run`. Elle a une association de composition avec la classe `Flask` (application web) et des associations fortes avec les classes `MLTrafficClassifier`, `RealNetworkCapture` et `MLTrafficDetector` qui sont instanciées en son sein.

La classe `RealNetworkCapture` comporte les attributs `packets: list`, `is_capturing: bool`, `stats: dict`, `capture_thread: Thread`, `should_stop: bool`, `connections_history: set`. Elle fournit les méthodes `get_active_connections_detailed`, `get_process_name`, `analyze_connection`, `start_capture`, `stop_capture`, `get_recent_packets`, `get_stats`. Elle dépend de la configuration (`CONFIG`) et du `Logger`.

La classe `MLDataPreprocessor` (dans @ids_ml_system/preprocessor.py) possède les attributs `scaler: StandardScaler`, `label_encoder: LabelEncoder`, `feature_names: list[str]`. Elle définit les méthodes `prepare_features`, `encode_ip`, `is_private_ip`, `fit_scaler`. Elle est utilisée (composition) par la classe `MLTrafficClassifier`.

La classe `MLTrafficClassifier` possède les attributs `model: RandomForestClassifier`, `is_trained: bool`, `accuracy: float`, `preprocessor: MLDataPreprocessor`. Elle expose les méthodes `load_model`, `is_legitimate_traffic`, `generate_training_data`, `train_model`, `predict`, `save_model`, `get_model_info`. Elle dépend de la configuration (`CONFIG`) pour certains paramètres (seuil de confiance) et de la bibliothèque scikit-learn.

La classe `MLTrafficDetector` comprend les attributs `traffic_collector: RealNetworkCapture`, `ml_classifier: MLTrafficClassifier`, `alerts: deque`, `is_monitoring: bool`, `monitor_thread: Thread`, `should_stop_monitoring: bool`, `stats: dict`, `recent_alerts: dict`, `alert_count_minute: int`, `last_alert_reset: float`. Elle propose les méthodes `should_generate_alert`, `analyze_traffic`, `classify_attack`, `calculate_severity`, `start_monitoring`, `stop_monitoring`, `get_recent_alerts`, `get_stats`, `debug_alerts`. Elle dépend de la configuration (`CONFIG`) et du `Logger`.

Enfin, la classe `Logger` (dans @ids_ml_system/logger.py) fournit des méthodes statiques telles que `add_console_log`, `add_traffic_log`, `add_alert_log`, `add_insecure_site`, `clear_all_logs`, et manipule des deques définis dans @ids_ml_system/config.py (`console_logs`, `traffic_logs`, `alert_logs`, `insecure_sites_logs`).

### 3.3 Conception de la base de données / stockage

Le système IDS-ML, dans sa version actuelle, ne s’appuie pas sur une base de données relationnelle ou NoSQL externe. Le stockage persistant est limité au fichier de modèle ML sauvegardé au format `joblib` (`ids_ml_model.joblib`), qui contient le classificateur Random Forest entraîné, le scaler associé et les métadonnées nécessaires (accuracy, liste des features). Les journaux (logs console, trafic, alertes, sites non sécurisés) sont conservés en mémoire dans des structures `deque` à capacité limitée définies dans @ids_ml_system/config.py : `console_logs` (maxlen=500), `traffic_logs` (maxlen=200), `alert_logs` (maxlen=200), `insecure_sites_logs` (maxlen=200).

Cette conception privilégie la simplicité et la légèreté : les journaux les plus récents sont disponibles pour consultation via l’interface web, mais ils ne sont pas archivés à long terme. Lorsqu’une deque atteint sa capacité maximale, les éléments les plus anciens sont automatiquement supprimés. Ce choix convient à un démonstrateur de laboratoire, mais devrait être révisé dans une perspective de déploiement en production, où la conservation et l’archivage des événements de sécurité constituent un besoin central (traçabilité, conformité, forensic).

La configuration globale du système est regroupée dans la constante `CONFIG` du fichier @ids_ml_system/config.py, qui définit notamment les paramètres suivants :

```python
CONFIG = {
    'ML_CONFIDENCE_THRESHOLD': 0.85,
    'ALERT_DEDUPLICATION_WINDOW': 300,
    'MAX_ALERTS_PER_MINUTE': 10,
    'WHITELIST_PROCESSES': ['svchost.exe', 'System', 'Registry', 'MsMpEng.exe'],
    'SUSPICIOUS_PORTS': [135, 139, 445, 3389, 22, 23, 21, 25, 110, 143]
}
```

Ces paramètres jouent un rôle déterminant dans le comportement du système, en particulier :

- `ML_CONFIDENCE_THRESHOLD`: seuil minimal de confiance pour considérer une prédiction ML comme une attaque et générer une alerte ; il est exploité dans la méthode `analyze_traffic` de `MLTrafficDetector`.  
- `ALERT_DEDUPLICATION_WINDOW`: durée (en secondes) pendant laquelle des alertes portant sur la même combinaison (source, destination, port, type d’attaque) sont considérées comme des doublons et ne sont pas régénérées.  
- `MAX_ALERTS_PER_MINUTE`: plafond du nombre d’alertes pouvant être produites par minute, afin d’éviter une inondation du système.  
- `WHITELIST_PROCESSES`: liste de noms de processus considérés comme a priori légitimes, utilisée à la fois dans la capture (`analyze_connection`) et dans le prétraitement des données (`is_whitelisted_process`).  
- `SUSPICIOUS_PORTS`: liste de ports considérés comme particulièrement sensibles (135, 139, 445, 3389, 22, 23, 21, 25, 110, 143), exploitée à la fois dans l’analyse des connexions et dans la génération de données d’entraînement.

Le Tableau 6 en propose une synthèse.

**Tableau 6 – Paramètres principaux de configuration**

| Paramètre | Valeur par défaut | Rôle |
|----------|-------------------|------|
| `ML_CONFIDENCE_THRESHOLD` | 0.85 | Seuil de confiance minimal pour déclencher une alerte basée sur le ML. |
| `ALERT_DEDUPLICATION_WINDOW` | 300 s | Fenêtre de temps pour éviter les alertes dupliquées similaires. |
| `MAX_ALERTS_PER_MINUTE` | 10 | Limite du nombre d’alertes par minute pour éviter l’inondation. |
| `WHITELIST_PROCESSES` | `['svchost.exe', 'System', 'Registry', 'MsMpEng.exe']` | Liste blanche de processus légitimes. |
| `SUSPICIOUS_PORTS` | `[135, 139, 445, 3389, 22, 23, 21, 25, 110, 143]` | Ports considérés comme sensibles ou souvent ciblés. |

### 3.4 Modélisation UML

#### 3.4.1 Diagramme de cas d’utilisation (description textuelle)

Le diagramme de cas d’utilisation (Figure 4) met en évidence les interactions entre l’acteur principal, l’« Utilisateur de l’IDS-ML », et le système.

**Figure 4 – Description textuelle du diagramme de cas d’utilisation**  
Un acteur unique, représenté comme un utilisateur humain, interagit avec six cas d’utilisation principaux : (1) « Démarrer la capture réseau » ; (2) « Arrêter la capture réseau » ; (3) « Activer la détection ML » ; (4) « Arrêter la détection ML » ; (5) « Entraîner le modèle ML » ; (6) « Consulter le tableau de bord de supervision ». Le cas d’utilisation « Consulter le tableau de bord de supervision » comprend lui-même les sous-fonctionnalités « Visualiser les statistiques globales », « Visualiser les alertes de sécurité », « Visualiser les connexions réseau », « Visualiser les sites non sécurisés » et « Consulter les journaux console ». Un septième cas d’utilisation, « Effacer les journaux et alertes », permet à l’utilisateur de réinitialiser l’état des journaux.

Les cas d’utilisation « Démarrer la capture réseau » et « Arrêter la capture réseau » impliquent respectivement les endpoints `/api/control/start_capture` et `/api/control/stop_capture`. Les cas « Activer la détection ML » et « Arrêter la détection ML` correspondent aux endpoints `/api/control/start_detection` et `/api/control/stop_detection`. « Entraîner le modèle ML » est associé à `/api/control/train_model`. « Consulter le tableau de bord de supervision » repose sur un rafraîchissement périodique des données via les endpoints `/api/stats`, `/api/console_logs`, `/api/traffic_logs`, `/api/alerts` et `/api/insecure_sites`. Enfin, « Effacer les journaux et alertes » invoque l’endpoint `/api/control/clear_logs`.

#### 3.4.2 Diagramme de séquence (description textuelle)

Le diagramme de séquence illustrant le processus de détection d’une attaque (Figure 5) peut être décrit comme suit.

**Figure 5 – Description textuelle du diagramme de séquence de détection**  
Sur l’axe horizontal figurent quatre lifelines : l’« Utilisateur », le « Navigateur web », l’« Application Flask (IDSFlaskApp) » et le « Cœur IDS-ML » (incluant `RealNetworkCapture`, `MLTrafficClassifier`, `MLTrafficDetector`). La séquence commence lorsque l’utilisateur clique sur le bouton « Détection ML » dans l’interface web. Le navigateur envoie une requête HTTP POST à l’endpoint `/api/control/start_detection`. L’application Flask reçoit cette requête et invoque la méthode `start_monitoring` du détecteur ML.

La méthode `start_monitoring` crée un thread d’analyse qui exécute en boucle `analyze_traffic`. À intervalles réguliers, `analyze_traffic` interroge `traffic_collector.get_recent_packets(30)` pour récupérer les dernières connexions observées. Pour chaque paquet, la méthode vérifie d’abord s’il s’agit de trafic HTTP non sécurisé (port 80 sans processus en liste blanche). Si c’est le cas, une alerte de type `HTTP_NON_SECURE` est générée et ajoutée à la deque d’alertes, puis consignée via le `Logger`.

Pour les autres paquets, `analyze_traffic` appelle `ml_classifier.predict(packet)`. Le classificateur prépare les features via le `MLDataPreprocessor`, applique le scaler et interroge le modèle Random Forest pour obtenir une prédiction et une probabilité d’attaque. Le résultat de cette prédiction est renvoyé au détecteur, qui décide, en fonction du seuil de confiance et des paramètres de configuration, de générer ou non une alerte. Si une alerte est créée, elle est stockée et transmise au `Logger`.

En parallèle, le navigateur interroge toutes les deux secondes l’endpoint `/api/alerts` pour récupérer les alertes récentes. L’application Flask renvoie la liste des alertes, qui sont ensuite affichées sur le tableau de bord.

#### 3.4.3 Diagramme d’activité (description textuelle)

Le diagramme d’activité du processus global de détection (Figure 6) peut être résumée ainsi.

**Figure 6 – Description textuelle du diagramme d’activité**  
L’activité commence par l’état « Démarrage du système IDS-ML ». Ensuite, deux activités peuvent être déclenchées indépendamment par l’utilisateur : « Démarrer la capture réseau » et « Entraîner ou charger le modèle ML ». La première conduit à une boucle d’activité « Capturer les connexions réseau » qui, à chaque itération, exécute `netstat`, filtre les connexions ESTABLISHED, extrait les informations pertinentes (IP, ports, PID, processus) et les stocke dans la liste `packets` et les journaux de trafic. La seconde activité initialise ou met à jour le modèle Random Forest et le scaler.

Lorsque l’utilisateur active la détection ML, une activité parallèle « Analyser le trafic avec ML » est lancée. Cette activité prend en entrée les connexions récentes et, pour chacune, suit un flot conditionnel : (1) si le port destination est 80 et que le processus n’est pas en liste blanche, déclencher la sous-activité « Générer alerte HTTP_NON_SECURE » ; (2) sinon, appeler la sous-activité « Prédire avec Random Forest ». Cette dernière comprend l’extraction des features, l’application du scaler, la prédiction, et conduit à un test sur la probabilité d’attaque et la confiance. Si cette probabilité dépasse le seuil et si les contrôles de déduplication et de limitation de débit sont satisfaits, l’activité « Générer alerte ML » est exécutée. Dans tous les cas, les journaux console sont mis à jour.

L’activité globale se termine lorsque l’utilisateur arrête la capture et la détection ML, ce qui conduit à la fin des boucles de capture et d’analyse.

---

## CHAPITRE 4 : IMPLÉMENTATION

### 4.1 Environnement de développement

L’implémentation du système IDS-ML repose sur un environnement technique cohérent centré autour du langage Python. Les principaux éléments sont les suivants :

- **Langage** : Python 3.x, qui offre une riche bibliothèque standard pour la gestion des processus, des threads, des structures de données et de la sérialisation, ainsi qu’un écosystème très développé pour le Machine Learning et les applications web.  
- **Framework web** : Flask 2.3.3, utilisé pour créer l’application web, définir les routes REST, gérer les requêtes HTTP et rendre les templates HTML.  
- **Bibliothèque de Machine Learning** : scikit-learn 1.3.0, fournissant l’implémentation du classificateur Random Forest (`RandomForestClassifier`), les fonctions de partitionnement du jeu de données (`train_test_split`), les métriques d’évaluation (`accuracy_score`) et les outils de prétraitement (`StandardScaler`).  
- **Dépendances complémentaires** : `numpy` pour la manipulation efficace de tableaux numériques, `pandas` pour la gestion tabulaire de données (notamment dans les extensions éventuelles de l’outil), `psutil` pour l’obtention d’informations sur les processus locaux associés aux connexions réseau, `joblib` pour la sérialisation et la désérialisation du modèle ML, `subprocess` pour l’appel à la commande `netstat`, `threading` pour l’exécution concurrente de la capture et de la détection.

L’environnement de développement inclut également les outils nécessaires pour exécuter localement l’application Flask, accéder à l’interface web via un navigateur moderne, et tester les différentes fonctionnalités. Le code est organisé sous la forme d’un package Python `ids_ml_system` contenant les modules principaux, complété par un répertoire `templates` pour le fichier `index.html`.

### 4.2 Module de capture réseau (@ids_ml_system/network_capture.py)

Le module @ids_ml_system/network_capture.py implémente la classe `RealNetworkCapture`, dont la responsabilité est de collecter en temps réel les connexions réseau actives sur la machine locale et de les enrichir avec des informations utiles pour la détection. Ce module s’appuie sur la commande système `netstat` (avec les options `-n -o` sous Windows) pour lister les connexions TCP en cours, et sur la bibliothèque `psutil` pour associer un PID à un nom de processus.

La méthode `get_active_connections_detailed` exécute `subprocess.run(['netstat', '-n', '-o'], ...)` et parcourt la sortie en recherchant les lignes comportant le mot-clé `ESTABLISHED` et le protocole `TCP`. Pour chaque ligne correspondante, elle extrait l’adresse locale, l’adresse distante et le PID du processus. Les adresses sont découpées en IP et port, et les connexions internes (remote_ip = 127.0.0.1 ou localhost) sont ignorées. Un identifiant unique de connexion est construit, et une structure de données représentant la connexion est créée, incluant les champs suivants :

- `timestamp` : horodatage de la détection (en secondes depuis l’époque) ;  
- `src_ip`, `dst_ip` : adresses IP source et destination ;  
- `src_port`, `dst_port` : ports source et destination ;  
- `protocol` : code numérique du protocole (6 pour TCP) ;  
- `packet_size` : taille de paquet simulée (valeur entière aléatoire entre 200 et 1500 octets) ;  
- `ttl` : valeur Time To Live simulée (aléatoire entre 30 et 255) ;  
- `process` : nom du processus obtenu via `psutil.Process(pid).name()` ;  
- `pid` : identifiant de processus ;  
- `status` : état de la connexion (ici `ESTABLISHED`) ;  
- `real_traffic` : indicateur booléen positionné à True ;  
- `connection_new` : indicateur True si la connexion n’a pas encore été vue auparavant.

La méthode `analyze_connection` enrichit ensuite cette structure en déterminant le service (`HTTP`, `HTTPS`, `DNS` ou `Port_<port>`), le niveau de risque (`LOW`, `MEDIUM`, `HIGH`) et le caractère sécurisé (`secure` booléen). Les informations de configuration sont utilisées pour :

- marquer comme **liste blanche** (`is_whitelisted`) les connexions dont le processus figure dans `WHITELIST_PROCESSES` ;  
- considérer comme `HIGH` les connexions dont le port de destination figure dans `SUSPICIOUS_PORTS`.

Les connexions nouvelles ainsi analysées sont ajoutées à la liste interne `packets`, le compteur `stats['total_packets']` est incrémenté, et des représentations simplifiées sont ajoutées aux journaux de trafic et aux journaux de sites non sécurisés (si le service n’est pas sécurisé, par exemple HTTP). Des messages détaillés sont également ajoutés à la console via le `Logger`.

La méthode `start_capture` lance la capture dans un thread dédié (`capture_thread`), ce qui permet de ne pas bloquer le thread principal. La boucle de capture appelle périodiquement `get_active_connections_detailed`, traite les nouvelles connexions, met à jour les statistiques, et effectue une pause de deux secondes entre chaque itération. La capture peut être arrêtée via `stop_capture`, qui positionne le drapeau `should_stop` et consigne un log de fin de capture.

Ce module assure ainsi la première étape de la chaîne de traitement : transformer des informations brutes sur les connexions réseau en objets structurés enrichis, stockés dans une liste accessible au module de détection.

### 4.3 Module de prétraitement (@ids_ml_system/preprocessor.py)

Le module @ids_ml_system/preprocessor.py implémente la classe `MLDataPreprocessor`, dont la fonction est de transformer les informations d’une connexion réseau en un vecteur de features numériques adapté à l’entrée du modèle de Machine Learning. Ce prétraitement est indispensable car les modèles comme Random Forest requièrent des entrées vectorielles numériques de taille fixe.

La classe `MLDataPreprocessor` définit une liste `feature_names` contenant les quatorze variables suivantes :

```text
packet_size, protocol, src_port, dst_port, ttl,
hour, minute, src_ip_encoded, dst_ip_encoded,
is_common_port, is_private_ip, packet_size_std,
is_whitelisted_process, is_suspicious_port
```

Ces features peuvent être décrites ainsi (Tableau 5).

**Tableau 5 – Description des 14 features extraites**

| Feature | Type | Description |
|--------|------|-------------|
| `packet_size` | Numérique | Taille du paquet (octets), simulée ou estimée. |
| `protocol` | Numérique | Code du protocole (6 pour TCP, 17 pour UDP, etc.). |
| `src_port` | Numérique | Port source de la connexion. |
| `dst_port` | Numérique | Port destination de la connexion. |
| `ttl` | Numérique | Valeur Time To Live (TTL) simulée, reflétant la distance réseau. |
| `hour` | Numérique | Heure courante (0-23) au moment de l’observation. |
| `minute` | Numérique | Minute courante (0-59) au moment de l’observation. |
| `src_ip_encoded` | Numérique | Encodage numérique de l’adresse IP source. |
| `dst_ip_encoded` | Numérique | Encodage numérique de l’adresse IP destination. |
| `is_common_port` | Binaire (0/1) | Indicateur si le port destination est un port courant (80, 443, 53, 22, etc.). |
| `is_private_ip` | Binaire (0/1) | Indicateur si l’IP source est dans un espace d’adressage privé (10.x.x.x, 172.16–31.x.x, 192.168.x.x). |
| `packet_size_std` | Numérique | Distance normalisée entre la taille du paquet et une valeur de référence (1000 octets). |
| `is_whitelisted_process` | Binaire (0/1) | Indicateur si le processus est en liste blanche (CONFIG['WHITELIST_PROCESSES']). |
| `is_suspicious_port` | Binaire (0/1) | Indicateur si le port destination est dans la liste `SUSPICIOUS_PORTS`. |

La méthode `prepare_features(packet_data)` extrait ces informations à partir du dictionnaire représentant un paquet. Les adresses IP sont encodées via `encode_ip`, qui convertit une adresse IPv4 en un entier basé sur les quatre octets, puis le normalise par une constante, ou retourne une valeur pseudo-aléatoire normalisée en cas de format non standard. La méthode `is_private_ip` détermine si l’adresse appartient à un espace privé en se basant sur les préfixes réservés.

Les indicateurs booléens `is_common_port`, `is_private_ip`, `is_whitelisted_process` et `is_suspicious_port` sont dérivés respectivement du port destination, de l’adresse IP source et des listes/configurations définies dans `CONFIG`. Le vecteur final est retourné sous forme de tableau NumPy de dimension `(1, 14)` prêt à être passé au scaler.

La méthode `fit_scaler` permet d’entraîner un `StandardScaler` sur un jeu de features (par exemple les données d’entraînement). Ce scaler sera ensuite utilisé par `MLTrafficClassifier` pour normaliser les vecteurs de features avant la prédiction.

Ce module encapsule donc les choix de représentation des données, qui sont cruciaux pour la performance du modèle.

### 4.4 Module de Machine Learning (@ids_ml_system/ml_model.py)

Le module @ids_ml_system/ml_model.py contient la classe `MLTrafficClassifier`, qui regroupe l’ensemble des opérations liées à l’apprentissage et à l’exploitation du modèle de Machine Learning.

#### 4.4.1 Configuration Random Forest

Dans la méthode `train_model`, après la génération des données d’entraînement et le prétraitement, un objet `RandomForestClassifier` est instancié avec les paramètres suivants :

```python
self.model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
```

Ces paramètres signifient que la forêt sera constituée de 100 arbres de décision, chaque arbre étant limité à une profondeur maximale de 20 niveaux. Au moins 5 échantillons sont requis pour effectuer une scission de nœud, et chaque feuille doit contenir au moins 2 échantillons. Le paramètre `random_state=42` assure la reproductibilité des résultats, tandis que `n_jobs=-1` permet d’exploiter tous les cœurs CPU disponibles pour accélérer l’entraînement.

Après l’entraînement sur les données normalisées, la performance du modèle est évaluée via `accuracy_score` sur un jeu de test représentant 20 % des données. L’accuracy obtenue est stockée dans l’attribut `accuracy` et consignée dans les journaux console.

#### 4.4.2 Génération des données d’entraînement

La méthode `generate_training_data(self, num_samples=2000)` construit un jeu de données synthétique destiné à l’entraînement et à la validation du modèle. Pour chaque exemple, la méthode détermine de façon aléatoire s’il s’agit de trafic normal ou malveillant, en respectant une proportion d’environ 85 % de trafic normal et 15 % de trafic malveillant. Les distributions de valeurs pour les champs (packet_size, ports, TTL, etc.) sont choisies de manière à refléter des tendances réalistes.

Pour le trafic normal, les paquets sont caractérisés par :

- une taille comprise entre 500 et 1500 octets ;  
- un port de destination parmi un ensemble courant (443, 80, 53, 993, 995) ;  
- un TTL compris entre 50 et 128 ;  
- un port source dans la plage 10000–60000 ;  
- des indicateurs `is_private_ip`, `is_whitelisted_process` et `is_suspicious_port` attribués de façon aléatoire cohérente (notamment `is_suspicious_port` généralement à 0).

Pour le trafic malveillant, plusieurs types d’attaques sont simulés :

- **port_scan** : petits paquets (20–100 octets) envoyés vers des ports considérés comme suspects (CONFIG['SUSPICIOUS_PORTS']), TTL relativement faible, indicateurs de processus non légitime et port suspect à 1 ;  
- **ddos** : petits paquets (10–100 octets) vers des ports web classiques (80, 443), TTL élevé (200–255) pour simuler une origine distante, indicateurs d’IP publique et de processus non légitime ;  
- **exploit** : paquets de taille moyenne (100–1000 octets) vers des ports souvent associés à des services vulnérables (135, 139, 445, 3389) ;  
- **suspicious** (catégorie générique) : paquets avec une large plage de tailles (10–5000 octets), ports choisis dans `SUSPICIOUS_PORTS`, protocole variant entre TCP (6) et UDP (17), TTL dans toute la plage possible, etc.

Dans tous les cas de trafic malveillant, la variable `label` est positionnée à 1, alors qu’elle est à 0 pour le trafic normal. Les autres features (heure, minute, encodages d’IP, indicateur de port courant, écart de taille de paquet) sont générées de manière cohérente. Le résultat de `generate_training_data` est un couple `(X, y)` où `X` est une matrice NumPy de dimension `(num_samples, 14)` et `y` un vecteur de labels binaires.

#### 4.4.3 Entraînement, sauvegarde et prédiction

La méthode `train_model` orchestre l’ensemble du processus : génération des données, partitionnement en train/test, entraînement du scaler et du modèle, évaluation, puis sauvegarde.

Après l’appel à `generate_training_data`, les données sont séparées en un jeu d’entraînement et un jeu de test via `train_test_split` avec un ratio 80/20 et un `random_state` fixé. Le scaler du préprocesseur est entraîné sur les données d’entraînement, puis utilisé pour transformer les données d’entraînement et de test. Le modèle Random Forest est ajusté sur les données normalisées d’entraînement, et l’accuracy est calculée sur les prédictions réalisées sur le jeu de test. Cette métrique, bien que partielle, donne une indication sur la capacité du modèle à généraliser sur des exemples non vus.

La méthode `save_model` sérialise ensuite un dictionnaire contenant le modèle, le scaler, l’accuracy et la liste des features dans un fichier `ids_ml_model.joblib`. La méthode `load_model` permet de recharger ce fichier au démarrage du système, si disponible.

La méthode `predict(self, packet_data)` est utilisée en temps réel par le module de détection. Elle commence par appliquer une heuristique de filtrage : si la fonction `is_legitimate_traffic` considère qu’il s’agit de trafic légitime (par exemple un navigateur connu se connectant à un site web en HTTPS ou HTTP sur un port courant), la méthode retourne directement une prédiction NORMAL avec une confiance élevée et une probabilité d’attaque faible, afin de réduire les faux positifs. Si le modèle n’est pas encore entraîné, la méthode adopte également une stratégie conservatrice en retournant NORMAL avec une confiance moyenne.

Dans le cas général, la méthode prépare les features via le préprocesseur, applique le scaler, et interroge le modèle Random Forest pour obtenir une prédiction (0 ou 1) et un vecteur de probabilités. La probabilité associée à la classe prédite est considérée comme la confiance globale, tandis que la probabilité de la classe d’attaque (1) est rapportée comme `probability_attack`. La méthode renvoie une structure contenant la prédiction textuelle (`NORMAL` ou `ATTACK`), la confiance, la probabilité d’attaque, le nombre de features utilisées et une justification générique.

### 4.5 Module de détection (@ids_ml_system/traffic_detector.py)

Le module @ids_ml_system/traffic_detector.py implémente la classe `MLTrafficDetector`, qui constitue le cœur de la logique de détection temps réel. Ce composant reçoit en entrée les connexions collectées par `RealNetworkCapture` et les passe au classificateur ML afin de décider s’il convient de générer des alertes.

La méthode `start_monitoring` crée un thread dédié qui exécute `analyze_traffic` en boucle tant que `is_monitoring` est vrai. Avant de démarrer ce thread, la méthode vérifie si le modèle ML est entraîné (`is_trained`) ; sinon, elle lance un entraînement automatique en consignant un avertissement dans la console. Elle consigne ensuite l’activation de la détection et le seuil de confiance utilisé (issu de `CONFIG['ML_CONFIDENCE_THRESHOLD']`).

La méthode `analyze_traffic` constitue la boucle principale. À chaque itération, elle récupère les trente dernières connexions (`get_recent_packets(30)`) et les traite une à une. Pour chaque paquet, plusieurs étapes sont réalisées :

1. **Mise à jour des statistiques** : le compteur `total_processed` est incrémenté.  
2. **Détection spécifique HTTP non sécurisé** : si le port destination est 80 et que le paquet n’est pas marqué comme whiteliste, une alerte particulière de type `HTTP_NON_SECURE` est créée avec une confiance et une probabilité d’attaque élevées (0,95), une sévérité `HIGH`, un service `HTTP` et un indicateur `ml_model` à False (car il ne s’agit pas d’une prédiction ML mais d’une règle heuristique). Cette alerte est ajoutée à la deque, consignée dans les logs et affichée dans la console.  
3. **Analyse ML** : pour les autres paquets, la méthode appelle `ml_classifier.predict(packet)` pour obtenir une prédiction. Le compteur `ml_predictions` est mis à jour, et un message de debug décrit la prédiction, la confiance et la raison fournie.  
4. **Génération d’alerte ML** : si la prédiction est `ATTACK`, si la confiance dépasse le seuil configuré, et si le paquet n’est pas whiteliste, la méthode appelle `classify_attack` pour déterminer un label d’attaque (par exemple `ATTACK_HIGH_CONFIDENCE`, `SUSPICIOUS_PORT_ACCESS`, `ANOMALY_DETECTED`, `SUSPICIOUS_ACTIVITY`), puis construit une structure d’alerte contenant les champs `id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `process`, `attack_type`, `confidence`, `probability_attack`, `severity`, `service`, `secure`, `ml_model`, `reason`, `features_used`.

Avant d’ajouter l’alerte à la deque, la méthode `should_generate_alert` est appelée pour vérifier si une alerte similaire n’a pas été générée récemment, et si le plafond `MAX_ALERTS_PER_MINUTE` n’est pas atteint. Cette méthode maintient un dictionnaire `recent_alerts` associant un identifiant d’alerte (basé sur la combinaison `src_ip-dst_ip-dst_port-attack_type`) à un timestamp, et supprime périodiquement les entrées trop anciennes. Si toutes les conditions sont réunies, l’alerte est ajoutée, les statistiques sont mises à jour, et un message d’alerte est consigné dans la console.

La méthode `calculate_severity` dérive la sévérité à partir du niveau de confiance : supérieure à 0,9 → `CRITICAL` ; supérieure à 0,8 → `HIGH` ; supérieure à 0,7 → `MEDIUM` ; sinon → `LOW`. Cette classification est utilisée pour colorer l’affichage des alertes dans l’interface web.

La méthode `get_recent_alerts` renvoie une liste d’alertes récentes, en veillant à convertir les types NumPy en types natifs Python (float, bool, list) pour assurer la sérialisation JSON correcte. La méthode `get_stats` calcule des agrégats tels que le nombre total de paquets traités, le nombre d’attaques détectées, le nombre de prédictions ML réalisées, le taux de détection (ratio attaques détectées / total traité) et l’état courant de la surveillance.

### 4.6 Interface web (@ids_ml_system/flask_app.py + @templates/index.html)

Le module @ids_ml_system/flask_app.py, déjà présenté au chapitre 2, joue un rôle central dans l’intégration entre le back-end IDS-ML et l’interface web. La classe `IDSFlaskApp` initialise les composants, configure les routes et expose une méthode `run` pour démarrer l’application Flask.

Les routes REST principales sont les suivantes :

- `/api/stats` : renvoie un objet JSON contenant les statistiques de trafic (`traffic.get_stats()`), les statistiques de détection (`detector.get_stats()`), les informations sur le modèle ML (`ml_classifier.get_model_info()`) et un état synthétique du système (`capture_active`, `detection_active`, `model_trained`).  
- `/api/console_logs` : renvoie la liste des messages console stockés dans `console_logs`.  
- `/api/traffic_logs` : renvoie la liste des derniers enregistrements de trafic (`traffic_logs`).  
- `/api/alert_logs` et `/api/alerts` : renvoient la liste des alertes (respectivement jusqu’à 50 ou un nombre spécifié).  
- `/api/insecure_sites` : renvoie la liste des sites non sécurisés détectés.  
- `/api/control/start_capture` et `/api/control/stop_capture` : contrôlent la capture réseau.  
- `/api/control/start_detection` et `/api/control/stop_detection` : contrôlent la détection ML.  
- `/api/control/train_model` : déclenche l’entraînement du modèle et renvoie l’accuracy.  
- `/api/control/load_model` : charge un modèle ML existant à partir du fichier `joblib`.  
- `/api/control/clear_logs` : efface tous les journaux et réinitialise les statistiques.  
- `/api/test/alert` : génère une alerte de test artificielle, utile pour vérifier le fonctionnement de l’interface.

Du côté client, le fichier @templates/index.html construit une interface de type tableau de bord. En haut de la page, un en-tête présente le titre « Système IDS avec Machine Learning », suivi d’une grille de six boutons permettant :

1. de démarrer la capture ;  
2. de l’arrêter ;  
3. d’activer la détection ML ;  
4. de l’arrêter ;  
5. d’entraîner le modèle ML ;  
6. d’effacer les journaux.

Une section de statistiques affiche le nombre total de paquets traités, le nombre d’alertes, le taux de détection et l’état de la détection ML (actif/inactif). Une autre section présente des informations sur le modèle ML : statut (entraîné ou non), accuracy, nombre de features et type d’algorithme.

La colonne de gauche contient une console texte simulant un terminal, dans laquelle les messages du `Logger` sont affichés avec des codes couleur en fonction de leur type (info, success, warning, error, alert, traffic), et une liste de trafic réseau présentant pour chaque connexion détectée le service, le processus associé, la destination et un indicateur de sécurité (cadenas fermé ou ouvert). La colonne de droite affiche les alertes de sécurité sous forme de cartes colorées, avec le type d’attaque, la sévérité, la confiance et les détails de la connexion. Une section supplémentaire liste les sites non sécurisés (trafic HTTP) avec le processus et la destination.

Le rafraîchissement dynamique des données est réalisé via la fonction `updateData`, appelée toutes les deux secondes avec `setInterval`. Cette fonction envoie des requêtes `fetch` en parallèle aux différents endpoints, puis appelle `updateConsole`, `updateTraffic`, `updateAlerts`, `updateInsecureSites`, `updateStats` et `updateMLInfo` pour mettre à jour le DOM. Des fonctions de notification (`showNotification`) fournissent un retour utilisateur immédiat lors des opérations de contrôle.

L’interface web constitue ainsi un élément essentiel de l’expérience utilisateur, en rendant visibles les mécanismes internes de capture, de détection et d’alerte.

---

## CHAPITRE 5 : TESTS ET RÉSULTATS

### 5.1 Plan de tests

L’évaluation du système IDS-ML repose sur un plan de tests structuré visant à couvrir à la fois les aspects fonctionnels (conformité aux spécifications) et les aspects de performance (qualité de la détection, comportement en charge modérée). Trois niveaux de tests peuvent être distingués : tests unitaires, tests d’intégration et tests de performance du modèle ML.

Les tests unitaires ciblent les fonctions critiques telles que le prétraitement des données, la génération de données d’entraînement, la prédiction, la logique de déduplication des alertes et la gestion des journaux. Des cas de test sont définis pour vérifier, par exemple, que la fonction `is_private_ip` identifie correctement les plages d’adresses privées, que le vecteur de features retourné par `prepare_features` possède bien la dimension attendue (1, 14) et des valeurs cohérentes, ou encore que la méthode `should_generate_alert` supprime les doublons d’alertes dans la fenêtre temporelle configurée.

Les tests d’intégration visent à vérifier le bon fonctionnement de bout en bout du pipeline : déclenchement de la capture, observation de connexions de test, activation de la détection ML, génération d’alertes et affichage correct dans l’interface web. Ils impliquent l’exécution de l’application Flask, l’accès via un navigateur, et l’utilisation des boutons de contrôle pour simuler différents scénarios (par exemple, lancement simultané de la capture et de la détection, ré-entraînement du modèle en cours de fonctionnement, effacement des journaux et vérification de la réinitialisation de l’affichage).

Les tests de performance du modèle ML portent sur la qualité de la classification sur le jeu de données synthétique. Ils comprennent le calcul de l’accuracy, de la précision, du rappel et du F1-score, ainsi que l’analyse de la matrice de confusion. Ces métriques sont calculées sur le jeu de test produit par `train_test_split` à partir des données générées par `generate_training_data`.

### 5.2 Tests unitaires des modules

Du point de vue des modules individuels, plusieurs vérifications peuvent être mentionnées.

Pour le module de prétraitement, des tests consistent à fournir des dictionnaires de paquets artificiels avec des valeurs connues et à vérifier que les features produites correspondent aux attentes. Par exemple, pour un paquet avec `src_ip = '192.168.1.10'`, `dst_ip = '8.8.8.8'`, `dst_port = 80`, il est attendu que `is_private_ip = 1`, `is_common_port = 1` et `is_suspicious_port = 0` (sauf si 80 a été inclut explicitement dans la liste des ports suspects). De même, pour un paquet dont le processus est `svchost.exe`, le flag `is_whitelisted_process` doit être égal à 1, en accord avec `WHITELIST_PROCESSES`.

Pour le module de génération de données, il est vérifié que la proportion de trafic normal et malveillant approche bien la cible de 85 %/15 % sur un grand nombre d’échantillons et que les valeurs de features respectent les bornes définies (par exemple TTL entre 1 et 255, ports dans les plages autorisées). On vérifie également que `X` a la bonne dimension et que les labels sont bien binaires.

Pour le module de détection, des tests ciblent la logique de seuil et de classification de sévérité. Par exemple, en injectant artificiellement des résultats ML avec `confidence = 0.95` et un port dans `SUSPICIOUS_PORTS`, `classify_attack` devrait retourner `ATTACK_HIGH_CONFIDENCE` ou `SUSPICIOUS_PORT_ACCESS` selon la logique définie, et `calculate_severity` doit retourner `CRITICAL`. La fonction `should_generate_alert` est testée en créant deux paquets quasi identiques à quelques secondes d’intervalle et en vérifiant que la seconde alerte est rejetée si elle survient dans la fenêtre de déduplication.

Enfin, pour le module Flask, des tests d’API (via des outils comme `curl` ou des bibliothèques de tests HTTP) peuvent être effectués pour s’assurer que les endpoints renvoient bien des réponses JSON conformes, avec les clés attendues (`traffic`, `detection`, `model_info`, `system_status` pour `/api/stats`, etc.) et des codes d’état HTTP appropriés.

### 5.3 Tests d’intégration

Les tests d’intégration consistent principalement à exécuter l’application dans un environnement de développement, à ouvrir l’interface web dans un navigateur et à manipuler les différents contrôles. Les scénarios typiques comprennent :

1. **Démarrage simple** : lancer l’application Flask, charger la page d’accueil, vérifier l’affichage initial des sections (console, trafic, alertes, sites non sécurisés, statistiques, informations ML).  
2. **Capture seule** : cliquer sur « Capture » pour démarrer la capture réseau sans activer la détection ML, générer du trafic réseau légitime (navigation web, mises à jour système) et observer l’apparition de nouvelles entrées dans la liste de trafic et dans la console, sans génération d’alertes.  
3. **Capture + détection ML** : activer la détection ML après démarrage de la capture. Vérifier que le modèle est entraîné si nécessaire, que les prédictions ML sont consignées dans la console, et que des alertes sont générées pour certains types de trafic simulé.  
4. **Arrêt et redémarrage** : arrêter la capture et la détection, puis les redémarrer, en vérifiant la stabilité du système et la réinitialisation appropriée des compteurs et indicateurs.  
5. **Effacement des journaux** : utiliser le bouton « Effacer » pour vider les journaux et les alertes, et s’assurer que les sections de l’interface sont mises à jour en conséquence (affichage de messages « Aucun trafic » ou « Aucune alerte »).

Dans l’ensemble, ces tests visent à valider la cohérence fonctionnelle du système et la bonne intégration entre les modules backend et l’interface utilisateur.

### 5.4 Évaluation du modèle ML

L’évaluation du modèle Random Forest repose sur les métriques classiques de classification binaire : accuracy, précision, rappel et F1-score. Sur le jeu de test issu des données synthétiques générées, l’accuracy mesure la proportion d’exemples correctement classés (normaux ou malveillants). La précision mesure, parmi les exemples prédits comme attaques, la fraction qui sont réellement des attaques. Le rappel mesure, parmi les attaques réelles, la fraction correctement identifiée par le modèle. Le F1-score synthétise précision et rappel en une moyenne harmonique.

En pratique, le modèle Random Forest entraîné avec 2000 exemples synthétiques (80 % entraînement, 20 % test) atteint typiquement une accuracy supérieure à 0,9 (valeur indicative), avec des niveaux de précision et de rappel satisfaisants sur la classe d’attaque, compte tenu du caractère artificiel des données. Ces résultats doivent toutefois être interprétés avec prudence : les données sont générées à partir de distributions contrôlées, ce qui peut favoriser le modèle par rapport à un contexte réel plus hétérogène.

#### 5.4.1 Matrice de confusion (description textuelle)

La matrice de confusion du modèle peut être décrite textuellement comme un tableau à double entrée où la ligne correspond à la classe réelle (NORMAL vs ATTACK) et la colonne à la classe prédite. On y trouve quatre cellules :

- **Vrai négatif (TN)** : nombre de connexions réellement normales et correctement prédites comme normales.  
- **Faux positif (FP)** : nombre de connexions réellement normales mais incorrectement prédites comme attaques.  
- **Faux négatif (FN)** : nombre de connexions réellement malveillantes mais incorrectement prédites comme normales.  
- **Vrai positif (VP)** : nombre de connexions réellement malveillantes et correctement prédites comme attaques.

Dans un scénario expérimental typique, la matrice de confusion peut présenter un nombre élevé de TN (la majorité du trafic étant normal), un nombre raisonnablement faible de FP (grâce à l’heuristique `is_legitimate_traffic` et au seuil de confiance), et un nombre de VP significatif reflétant la capacité du modèle à reconnaître les patterns d’attaque simulés. Le nombre de FN doit être surveillé attentivement car ils représentent des attaques non détectées ; leur réduction nécessite soit un ajustement des paramètres du modèle, soit un enrichissement des features ou des données d’entraînement.

### 5.5 Analyse des performances

#### 5.5.1 Temps de réponse

Le temps de réponse global du système dépend principalement de trois facteurs : (1) la latence de la commande `netstat` pour extraire les connexions en cours ; (2) le temps d’exécution de la boucle de capture et d’analyse, y compris le prétraitement et la prédiction ML ; (3) la fréquence du polling HTTP par l’interface web. En pratique, la capture est effectuée toutes les deux secondes, ce qui laisse suffisamment de temps pour exécuter `netstat`, parse r la sortie, mettre à jour les structures de données et effectuer quelques prédictions ML sur une poignée de connexions nouvelles.

Le modèle Random Forest, una fois entraîné, offre des temps de prédiction très courts par échantillon (quelques millisecondes ou moins), ce qui rend son utilisation adaptée à un contexte de détection temps réel à faible volume (comme c’est le cas pour un poste de travail individuel). La normalisation des features via `StandardScaler` ajoute un surcoût négligeable. L’application Flask répond rapidement aux requêtes `/api/stats`, `/api/alerts`, etc., car elle se contente de sérialiser des structures de données déjà en mémoire.

#### 5.5.2 Taux de faux positifs

Le taux de faux positifs (FP) est un indicateur critique pour l’acceptabilité du système par les utilisateurs. Un IDS qui génère trop d’alertes injustifiées est rapidement ignoré ou désactivé, ce qui annule son utilité. Dans IDS-ML, plusieurs mécanismes concourent à réduire les FP :

- la fonction `is_legitimate_traffic` dans `MLTrafficClassifier`, qui marque comme légitimes certains trafics typiques (par exemple un navigateur web vers des ports 80/443) ;  
- l’utilisation d’une liste blanche de processus (`WHITELIST_PROCESSES`) pour exclure de l’analyse les connexions lancées par des composants système réputés sûrs ;  
- le seuil de confiance `ML_CONFIDENCE_THRESHOLD`, qui évite de déclencher des alertes pour des prédictions trop incertaines ;  
- la fenêtre de déduplication et la limite d’alertes par minute, qui évitent qu’un même comportement marginal génère une avalanche d’alertes.

Malgré ces précautions, il peut subsister des FP, en particulier si la distribution réelle du trafic diffère sensiblement de celle des données d’entraînement synthétiques. Par exemple, un outil de sauvegarde ou de synchronisation cloud effectuant des connexions sur des ports jugés sensibles peut être classé à tort comme suspect. La réduction de ces FP nécessiterait un affinement des règles heuristiques et/ou un enrichissement du jeu de données pour mieux couvrir les cas légitimes.

---

## CHAPITRE 6 : CONCLUSION ET PERSPECTIVES

### 6.1 Bilan du projet

Ce mémoire a présenté la conception, l’implémentation et l’évaluation d’un système de détection d’intrusion basé sur le Machine Learning (IDS-ML) destiné à la surveillance temps réel des connexions réseau d’une machine. Le système s’appuie sur une architecture modulaire en Python, intégrant un module de capture réseau basé sur `netstat` et `psutil`, un préprocesseur de données extrayant quatorze variables décrivant chaque connexion, un classificateur Random Forest entraîné sur des données synthétiques, un module de détection appliquant une logique métier pour la génération d’alertes, et une interface web de supervision construite avec Flask et Tailwind CSS.

Les principaux objectifs fixés ont été atteints : un prototype fonctionnel permet de démarrer et d’arrêter la capture réseau, d’activer et désactiver la détection ML, d’entraîner le modèle à la demande, d’afficher en temps réel les statistiques de trafic et de détection, les journaux et les alertes, et de gérer la liste des sites non sécurisés. Le modèle Random Forest, configuré avec des paramètres raisonnables (`n_estimators=100`, `max_depth=20`, `min_samples_split=5`, `min_samples_leaf=2`), atteint des performances satisfaisantes sur les données d’entraînement synthétiques, et le système intègre des mécanismes visant à limiter les faux positifs.

D’un point de vue pédagogique, le projet illustre de manière concrète la chaîne complète d’un IDS-ML : depuis la collecte des données brutes jusqu’à la visualisation des alertes sur une interface web moderne, en passant par le prétraitement et l’apprentissage automatique. Il met en lumière les choix de conception nécessaires pour concilier contraintes de temps réel, qualité de la détection et ergonomie de l’interface.

### 6.2 Difficultés rencontrées

Plusieurs difficultés ont été rencontrées au cours du projet. En premier lieu, la capture réseau dépendante de la commande `netstat` et de la bibliothèque `psutil` se heurte à la diversité des systèmes d’exploitation et des formats de sortie. Le module `RealNetworkCapture` doit gérer des cas d’erreur potentiels (commandes échouées, absence de PID, modifications de format), ce qui complique la robustesse de l’implémentation.

En second lieu, l’absence de jeu de données réel labellisé adapté au contexte précis de la machine surveillée a conduit au choix de générer des données d’entraînement synthétiques. Si cette approche est suffisante pour obtenir un modèle de démonstration, elle limite la validité externe des résultats : un modèle entraîné sur des données synthétiques peut se comporter de manière inattendue face à un trafic réel plus riche et plus varié. La conception de distributions de génération réalistes nécessite de solides connaissances sur les profils de trafic typiques et les signatures d’attaques.

Une autre difficulté réside dans la gestion des faux positifs et des faux négatifs. Trouver un compromis satisfaisant entre sensibilité (capacité à détecter un maximum d’attaques) et spécificité (limitation des alertes injustifiées) implique des ajustements subtils du seuil de confiance, de la liste blanche de processus, des ports considérés comme suspects, et potentiellement des distributions de données d’entraînement. Une mauvaise calibration peut conduire soit à un système trop silencieux (nombre important de faux négatifs), soit à un système trop bruyant (trop de faux positifs).

Enfin, l’intégration de tous les composants dans une application cohérente demande une attention particulière à la synchronisation entre threads, à la gestion des ressources, à la sérialisation des données (conversion des types NumPy), et à la gestion des erreurs dans un contexte web. Ces aspects relèvent de l’ingénierie logicielle et dépassent le seul cadre de la modélisation ML.

### 6.3 Perspectives d’amélioration

Plusieurs pistes d’amélioration et de prolongement peuvent être envisagées à l’issue de ce travail.

Une première perspective concerne l’intégration de techniques de Deep Learning. Des modèles de type LSTM (Long Short-Term Memory) ou GRU (Gated Recurrent Unit) pourraient être utilisés pour modéliser explicitement la dimension séquentielle du trafic réseau, en considérant non plus des connexions indépendantes mais des séquences de paquets ou de flux. Des réseaux convolutionnels (CNN) pourraient quant à eux être appliqués à des représentations matricielles du trafic (par exemple des cartes de flux) pour capturer des patterns locaux complexes [14]. Toutefois, ces approches exigeraient un volume de données important et des ressources de calcul plus conséquentes.

Une deuxième perspective serait d’améliorer la capture réseau en remplaçant l’utilisation de `netstat` par une bibliothèque de plus bas niveau comme Scapy. Scapy permet de capturer et de manipuler des paquets individuels, de reconstituer des flux complets, d’accéder à des champs de protocole détaillés et de générer du trafic. L’adoption de Scapy ouvrirait la voie à l’extraction de features plus riches (taille réelle des paquets, drapeaux TCP, durées de connexions, séquences de paquets) et à la détection de comportements plus fins. En contrepartie, elle impliquerait une augmentation significative de la complexité et des exigences de performance.

Une troisième perspective concerne la persistance des données. L’utilisation de structures `deque` en mémoire est suffisante pour une démonstration, mais un système opérationnel devrait archiver les journaux de trafic et les alertes dans une base de données (relationnelle ou NoSQL) afin de permettre des analyses a posteriori, des corrélations sur une longue période, et la satisfaction d’exigences réglementaires. L’intégration d’une base de données (par exemple PostgreSQL ou Elasticsearch) et d’un mécanisme de rotation/archivage des journaux constituerait une évolution naturelle.

Enfin, l’amélioration de l’interface web et de l’expérience utilisateur représente une autre direction possible : ajout de graphes temporels des alertes, filtres et recherches sur les journaux, visualisation géographique de certaines IP, personnalisation des règles et des seuils, gestion d’utilisateurs et de rôles, intégration avec des systèmes de notification externes (email, messagerie instantanée).

Ces perspectives montrent que le prototype IDS-ML développé dans ce mémoire peut servir de point de départ à des travaux plus ambitieux combinant recherche en Machine Learning, ingénierie logicielle et cybersécurité opérationnelle.

---

## Bibliographie

[1] Stallings, W., "Network Security Essentials: Applications and Standards", 6th Edition, Pearson, 2020.

[2] ENISA, "Threat Landscape 2023: Mapping the Threats of the Digital Age", European Union Agency for Cybersecurity, 2023.

[3] Scarfone, K., Mell, P., "Guide to Intrusion Detection and Prevention Systems (IDPS)", NIST Special Publication 800-94, 2007.

[4] Axelsson, S., "Intrusion Detection Systems: A Survey and Taxonomy", Technical Report, Chalmers University of Technology, 2000.

[5] Northcutt, S., Novak, J., "Network Intrusion Detection", 3rd Edition, New Riders, 2002.

[6] Denning, D. E., "An Intrusion-Detection Model", IEEE Transactions on Software Engineering, vol. SE-13, no. 2, pp. 222–232, 1987.

[7] Liao, H. J., Lin, C. H. R., Lin, Y. C., Tung, K. Y., "Intrusion detection system: A comprehensive review", Journal of Network and Computer Applications, vol. 36, no. 1, pp. 16–24, 2013.

[8] Bishop, C. M., "Pattern Recognition and Machine Learning", Springer, 2006.

[9] Hastie, T., Tibshirani, R., Friedman, J., "The Elements of Statistical Learning", 2nd Edition, Springer, 2009.

[10] Breiman, L., "Random Forests", Machine Learning, vol. 45, no. 1, pp. 5–32, 2001.

[11] Tavallaee, M., Bagheri, E., Lu, W., Ghorbani, A. A., "A detailed analysis of the KDD CUP 99 data set", Proceedings of the 2nd IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009.

[12] Moustafa, N., Slay, J., "UNSW-NB15: A comprehensive data set for network intrusion detection systems", Military Communications and Information Systems Conference (MilCIS), 2015.

[13] Ahmad, I. et al., "Network intrusion detection system: A systematic study of machine learning and deep learning approaches", Transactions on Emerging Telecommunications Technologies, 2021.

[14] Kim, J., Kim, J., Shim, J., Choi, J., "CNN-based network intrusion detection against denial-of-service attacks", Electronics Letters, vol. 54, no. 7, pp. 419–421, 2018.

[15] Grinberg, M., "Flask Web Development: Developing Web Applications with Python", 2nd Edition, O’Reilly, 2018.

[16] Tailwind Labs, "Tailwind CSS Documentation", https://tailwindcss.com/docs, consulté en 2024.

[17] Scarfone, K., Grance, T., "Guide to Computer Security Log Management", NIST Special Publication 800-92, 2006.

---

## Annexes

### Annexe A : Code source des modules principaux

Cette annexe présente des extraits significatifs du code réel du projet, afin d’illustrer la structure des modules et l’implémentation effective des principales fonctionnalités. Pour des raisons de lisibilité, seuls les blocs les plus représentatifs sont reproduits ici ; le lecteur est invité à consulter directement les fichiers référencés pour le détail exhaustif.

#### A.1 Module `ids_ml_system/network_capture.py`

```python
# ids_ml_system/network_capture.py
"""Capture réseau en temps réel"""
import time
import random
import subprocess
import threading
import psutil
from datetime import datetime
from .logger import Logger
from .config import CONFIG

class RealNetworkCapture:
    def __init__(self):
        self.packets = []
        self.is_capturing = False
        self.stats = {'total_packets': 0, 'packets_per_second': 0}
        self.capture_thread = None
        self.should_stop = False
        self.connections_history = set()
        Logger.add_console_log("✅ Capture réseau initialisée")

    def get_active_connections_detailed(self):
        """Capture les connexions réseau ACTIVES en temps réel"""
        try:
            result = subprocess.run(
                ['netstat', '-n', '-o'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )

            if result.returncode != 0:
                return []

            connections = []

            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line and 'TCP' in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        try:
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            pid = parts[4] if len(parts) > 4 else 'N/A'

                            local_ip, local_port = local_addr.rsplit(':', 1)
                            remote_ip, remote_port = remote_addr.rsplit(':', 1)

                            if remote_ip in ['127.0.0.1', 'localhost']:
                                continue

                            conn_id = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"

                            if conn_id not in self.connections_history:
                                self.connections_history.add(conn_id)
                                process_name = self.get_process_name(pid)
                                packet_size = random.randint(200, 1500)
                                ttl = random.randint(30, 255)

                                connections.append({
                                    'timestamp': time.time(),
                                    'src_ip': local_ip,
                                    'dst_ip': remote_ip,
                                    'src_port': int(local_port),
                                    'dst_port': int(remote_port),
                                    'protocol': 6,
                                    'packet_size': packet_size,
                                    'ttl': ttl,
                                    'process': process_name,
                                    'pid': pid,
                                    'status': 'ESTABLISHED',
                                    'real_traffic': True,
                                    'connection_new': True
                                })
                        except (ValueError, IndexError):
                            continue

            return connections

        except Exception as e:
            Logger.add_console_log(f"❌ Erreur capture connexions: {e}", "error")
            return []
```

#### A.2 Module `ids_ml_system/preprocessor.py`

```python
# ids_ml_system/preprocessor.py
"""Préprocessing des données pour le ML"""
import numpy as np
from datetime import datetime
from sklearn.preprocessing import StandardScaler, LabelEncoder
from .logger import Logger
from .config import CONFIG

class MLDataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = [
            'packet_size', 'protocol', 'src_port', 'dst_port', 'ttl',
            'hour', 'minute', 'src_ip_encoded', 'dst_ip_encoded',
            'is_common_port', 'is_private_ip', 'packet_size_std',
            'is_whitelisted_process', 'is_suspicious_port'
        ]
        Logger.add_console_log("✅ Preprocesseur ML initialisé")

    def prepare_features(self, packet_data):
        """Prépare les features pour le modèle ML"""
        try:
            packet_size = packet_data.get('packet_size', 0)
            protocol = packet_data.get('protocol', 0)
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            ttl = packet_data.get('ttl', 64)

            now = datetime.now()
            hour = now.hour
            minute = now.minute

            src_ip_encoded = self.encode_ip(packet_data.get('src_ip', '0.0.0.0'))
            dst_ip_encoded = self.encode_ip(packet_data.get('dst_ip', '0.0.0.0'))

            is_common_port = 1 if dst_port in [80, 443, 53, 22, 21, 25, 110, 143] else 0
            is_private_ip = 1 if self.is_private_ip(packet_data.get('src_ip', '')) else 0
            packet_size_std = abs(packet_size - 1000) / 500

            process_name = packet_data.get('process', '').lower()
            is_whitelisted_process = 1 if any(
                whitelist.lower() in process_name for whitelist in CONFIG['WHITELIST_PROCESSES']
            ) else 0
            is_suspicious_port = 1 if dst_port in CONFIG['SUSPICIOUS_PORTS'] else 0

            features = [
                packet_size, protocol, src_port, dst_port, ttl,
                hour, minute, src_ip_encoded, dst_ip_encoded,
                is_common_port, is_private_ip, packet_size_std,
                is_whitelisted_process, is_suspicious_port
            ]

            return np.array(features).reshape(1, -1)

        except Exception as e:
            Logger.add_console_log(f"❌ Erreur préprocessing: {e}", "error")
            return np.array([0] * 14).reshape(1, -1)
```

#### A.3 Module `ids_ml_system/ml_model.py`

```python
# ids_ml_system/ml_model.py
"""Modèle de Machine Learning"""
import os
import random
import joblib
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from .preprocessor import MLDataPreprocessor
from .logger import Logger
from .config import CONFIG

class MLTrafficClassifier:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.accuracy = 0.0
        self.preprocessor = MLDataPreprocessor()
        Logger.add_console_log("✅ Classificateur ML initialisé")

    def generate_training_data(self, num_samples=2000):
        """Génère des données d'entraînement réalistes"""
        Logger.add_console_log("🤖 Génération des données d'entraînement...")
        features_list = []
        labels_list = []
        for i in range(num_samples):
            # 85% de trafic normal, 15% de trafic malveillant
            if random.random() < 0.85:
                # Trafic normal
                packet_size = random.randint(500, 1500)
                dst_port = random.choice([443, 80, 53, 993, 995])
                protocol = 6
                ttl = random.randint(50, 128)
                src_port = random.randint(10000, 60000)
                is_private_ip = random.choice([0, 1])
                is_whitelisted_process = random.choice([0, 1])
                is_suspicious_port = 0
                label = 0
            else:
                # Trafic malveillant
                attack_type = random.choice(['port_scan', 'ddos', 'exploit', 'suspicious'])
                # ... (logique détaillée dans le code complet)
                label = 1
            # Construction du vecteur de features puis ajout à features_list / labels_list
        Logger.add_console_log(f"✅ Données d'entraînement générées: {len(features_list)} échantillons")
        return np.array(features_list), np.array(labels_list)

    def train_model(self):
        """Entraîne le modèle Random Forest"""
        try:
            Logger.add_console_log("🎯 Début de l'entraînement du modèle ML...")
            X, y = self.generate_training_data(2000)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            self.preprocessor.fit_scaler(X_train)
            X_train_scaled = self.preprocessor.scaler.transform(X_train)
            X_test_scaled = self.preprocessor.scaler.transform(X_test)
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_scaled, y_train)
            y_pred = self.model.predict(X_test_scaled)
            self.accuracy = accuracy_score(y_test, y_pred)
            self.is_trained = True
            Logger.add_console_log(f"✅ Modèle Random Forest entraîné avec succès!", "success")
            Logger.add_console_log(f"📊 Accuracy: {self.accuracy:.2%}", "success")
            self.save_model()
            return self.accuracy
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur entraînement modèle: {e}", "error")
            return 0.0
```

#### A.4 Module `ids_ml_system/traffic_detector.py`

```python
# ids_ml_system/traffic_detector.py
"""Détecteur de trafic avec ML"""
import time
from datetime import datetime
from collections import deque
import numpy as np
import threading
from .logger import Logger
from .config import CONFIG

class MLTrafficDetector:
    def __init__(self, traffic_collector, ml_classifier):
        self.traffic_collector = traffic_collector
        self.ml_classifier = ml_classifier
        self.alerts = deque(maxlen=200)
        self.is_monitoring = False
        self.monitor_thread = None
        self.should_stop_monitoring = False
        self.stats = {
            'attacks_detected': 0,
            'total_processed': 0,
            'ml_predictions': 0
        }
        self.recent_alerts = {}
        self.alert_count_minute = 0
        self.last_alert_reset = time.time()
        Logger.add_console_log("✅ Détecteur ML initialisé")

    def analyze_traffic(self):
        """Analyse le trafic avec le modèle ML"""
        while self.is_monitoring and not self.should_stop_monitoring:
            try:
                packets = self.traffic_collector.get_recent_packets(30)
                for packet in packets:
                    if self.should_stop_monitoring:
                        break
                    self.stats['total_processed'] += 1
                    # Détection HTTP non sécurisé puis détection ML avec seuil de confiance
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur analyse trafic: {e}", "error")
                time.sleep(3)
```

#### A.5 Module `ids_ml_system/flask_app.py` et template `templates/index.html`

```python
# ids_ml_system/flask_app.py
"""Application Flask principale"""
import os
import traceback
from flask import Flask, render_template, jsonify, request
from datetime import datetime
from .config import console_logs, traffic_logs, alert_logs, insecure_sites_logs, CONFIG
from .logger import Logger
from .ml_model import MLTrafficClassifier
from .network_capture import RealNetworkCapture
from .traffic_detector import MLTrafficDetector

class IDSFlaskApp:
    def __init__(self, template_folder=None):
        # Initialisation du dossier templates et de l'application Flask
        self.app = Flask(__name__, template_folder=template_folder or 'templates')
        self.setup_components()
        self.setup_routes()

    def setup_components(self):
        """Initialise tous les composants"""
        self.ml_classifier = MLTrafficClassifier()
        self.traffic_collector = RealNetworkCapture()
        self.detector = MLTrafficDetector(self.traffic_collector, self.ml_classifier)
        # ...

    def setup_routes(self):
        """Configure toutes les routes Flask"""
        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/api/stats')
        def api_stats():
            traffic_stats = self.traffic_collector.get_stats()
            detection_stats = self.detector.get_stats()
            model_info = self.ml_classifier.get_model_info()
            return jsonify({
                'traffic': traffic_stats,
                'detection': detection_stats,
                'model_info': model_info,
            })
        # ... (autres routes d'API et de contrôle)
```

```html
<!-- Extrait de templates/index.html -->
<div class="grid grid-cols-1 md:grid-cols-6 gap-4 mb-6">
    <button onclick="startCapture()" class="bg-green-500 hover:bg-green-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-play"></i> Capture
    </button>
    <button onclick="stopCapture()" class="bg-red-500 hover:bg-red-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-stop"></i> Arrêter
    </button>
    <button onclick="startDetection()" class="bg-blue-500 hover:bg-blue-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-brain"></i> Détection ML
    </button>
    <button onclick="stopDetection()" class="bg-orange-500 hover:bg-orange-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-pause"></i> Arrêter ML
    </button>
    <button onclick="trainModel()" class="bg-purple-500 hover:bg-purple-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-robot"></i> Entraîner ML
    </button>
    <button onclick="clearLogs()" class="bg-gray-500 hover:bg-gray-600 text-white p-3 rounded-lg flex items-center justify-center gap-2 transition-all">
        <i class="fas fa-trash"></i> Effacer
    </button>
</div>
```

### Annexe B : Captures d’écran de l’interface

Cette annexe illustre l’interface réelle de l’IDS-ML au travers de plusieurs captures d’écran. Les fichiers d’images correspondants peuvent être enregistrés, par exemple, dans un répertoire `captures/` du projet, puis référencés dans ce mémoire comme indiqué ci-dessous.

#### B.1 Tableau de bord au démarrage

![Capture 1 – Tableau de bord initial](captures/idsml_dashboard_initial.png)

Figure B.1 – Vue globale du tableau de bord immédiatement après le démarrage du système. La console affiche un message « Système IDS ML démarré... », les sections « Traffic Réseau », « Alertes de Sécurité » et « Sites Non Sécurisés » indiquent l’absence de données. Les tuiles de statistiques affichent 0 paquets, 0 alertes, un taux de détection de 0 % et un état de détection ML « INACTIF ».

#### B.2 Tableau de bord avec capture réseau active

![Capture 2 – Trafic réseau chiffré](captures/idsml_dashboard_https_traffic.png)

Figure B.2 – Tableau de bord après démarrage de la capture et navigation web vers plusieurs sites HTTPS. La section « Traffic Réseau » présente une liste de connexions sécurisées (icône de cadenas fermé) avec le nom du processus navigateur, les destinations et l’horodatage. La console montre des messages d’information sur les nouvelles connexions et les statistiques de trafic.

#### B.3 Tableau de bord avec alertes ML

![Capture 3 – Alertes générées par le modèle ML](captures/idsml_dashboard_alerts.png)

Figure B.3 – Tableau de bord après activation de la détection ML et génération de quelques alertes. La section « Alertes de Sécurité » affiche des cartes rouges avec des icônes d’alerte, le type d’attaque (par exemple `SUSPICIOUS_PORT_ACCESS`), la sévérité (CRITICAL ou HIGH) et la confiance associée. La tuile de statistiques « Alertes » indique un nombre non nul d’alertes, et le taux de détection est mis à jour.

#### B.4 Liste des sites non sécurisés

![Capture 4 – Sites non sécurisés détectés](captures/idsml_insecure_sites.png)

Figure B.4 – Vue de la section « Sites Non Sécurisés » après détection de trafic HTTP non chiffré. Chaque entrée affiche le service HTTP, le processus à l’origine de la connexion, la destination et un niveau de risque, sur fond jaune.

### Annexe C : Guide d’installation

Cette annexe fournit un guide synthétique pour l’installation et l’exécution du système IDS-ML.

1. **Prérequis**  
   - Système d’exploitation : Windows ou Linux avec accès à la commande `netstat` et installation de Python 3.x.  
   - Outils : pip pour la gestion des packages Python.  

2. **Installation des dépendances**  
   Dans le répertoire du projet, installer les dépendances requises (les noms peuvent varier selon le fichier de configuration fourni) :

   ```bash
   pip install flask==2.3.3 scikit-learn==1.3.0 numpy pandas psutil joblib
   ```

3. **Lancement de l’application**  
   - S’assurer que le répertoire `templates` contient le fichier `index.html`.  
   - Exécuter le script principal (par exemple `python main.py` ou `python -m ids_ml_system.flask_app` selon la configuration).  
   - Noter l’URL d’accès affichée dans la console (généralement `http://localhost:5000`).

4. **Utilisation de l’interface**  
   - Ouvrir un navigateur web moderne et accéder à l’URL de l’application.  
   - Utiliser les boutons de contrôle pour démarrer la capture, activer la détection ML, entraîner le modèle et effacer les journaux.  
   - Observer en temps réel le trafic, les alertes et les statistiques.  

5. **Arrêt du système**  
   - Arrêter la capture et la détection via l’interface ou en interrompant le processus Python (Ctrl+C dans le terminal).  
   - Sauvegarder éventuellement le fichier de modèle `ids_ml_model.joblib` pour un futur rechargement.

Ce guide vise à permettre à un utilisateur disposant de connaissances de base en Python et en réseaux de déployer rapidement le prototype IDS-ML et d’en explorer les capacités.