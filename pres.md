---
## Presentation personelle pour htmb

Je m'appelle Henry Bambury (alias `htmb` sur la plateforme), j'ai 23 ans (16/12/1999) donc je suis en catégorie Senior.

Concernant mon parcours, j'ai fait prépa MP option info puis j'ai intégré polytechnique où j'ai suivi la spécialisation MAT-INFO.
Ensuite, j'ai effectué ma dernière année en master de Maths et Fondements de l'informatique à Oxford.

Je pense avoir un bon bagage mathématique notemment sur les courbes elliptiques, et de bonnes connaissances en crypto.

Maintenant, j'ai commencé une thèse dans l'équipe CASCADE au DIENS. Je travaille sur l'attaque de problèmes sous-jacents à la sécurité des protocoles post-quantiques à base de réseaux algébriques, sous la direction de Phong Nguyen.

Mon expérience en CTF est assez limitée, mais je suis capable d'apprendre très vite. J'ai participé pour la première fois au FCSC en 2022. J'avais adoré faire le préchall. Depuis je me suis inscrit sur Cryptohack, PicoCTF et TryHackMe pour apprendre quelques bases.

Par contre, j'ai pas mal d'expérience sur les compétitions scientifiques, notamment en équipe et en temps limité. J'aide à entrainer les jeunes pour les olympiades internationales en maths/ITYM, et quand j'étais à l'X je me suis mis à la programmation compétitive et j'ai pu être dans l'équipe qui a remporté une médaille d'argent au SWERC en 2021 (bon j'étais remplaçant mais c'est plus classe si je le dis pas).

J'aimerais utiliser cette oportunité pour en apprendre beaucoup plus sur le monde des CTF et de la sécurité informatique.

## Mon déroulé du FCSC 

Ici je vais rapidement présenter dans les grandes lignes ce que j'ai fait pendant le FCSC et les idées que j'ai eu, dans l'ordre chronologique.

- Weekend du 13/14 : un ami me rappelle que le FCSC commence bientôt, je vais vite résoudre le pré-chall. Je suis resté bloqué un peu sur l'interprétation du labyrinthe lors du reverse à cause d'une mauvaise lecture des pointeurs, mais je m'y remets le lendemain et ça marche. 
- Vendredi 21 : le FCSC commence, je résouds les deux chals crypto Elliptic avec la même commande sage. Ensuite je commence à chercher Grabin qui m'attire particulièrement. Je vois que le problème est équivalent à factoriser un RSA1024 où q~2p. Je pense à la méthode de Fermat mais c'est trop lent. Je vois que les gens ont flag le hash qui rit donc je m'empresse de le résoudre (cf writeup).
- Samedi 22 : ok, clairement les gens sont plus forts que moi dans les autres catégories, pour maximiser mes chances de qualif je décide de ne regarder que les challs crypto. Je regarde Pain in the Hash et je lis beaucoup de littérature sur le Generalized Birthday Problem et l'attaque de Wagner. Malheureusement la complexité est trop élevée dans les $2^{50}$.
- Dimanche 23 : Je pars à Eurocrypt, j'étudie un peu Cry Me dans le train, où je fais un peu de maths pour me rendre compte qu'un solve est essentiellement équivalent à retrouver la clé secrète.
- Lundi - Jeudi : Je ne travaille pas beaucoup, mais j'essaye de faire marcher une attaque à base de réseaux sur Cry Me. Le lendemain je croise de loin Nadia Heninger dont je viens de lire le papier la veille, c'est un signe je dois plus être très loin. Le jeudi soir en essayant d'adapter la méthode des biased nonces à notre cas je finis par tomber sur l'article de 1997 qui explique exactement la méthode à suivre. Je l'implémente et je retrouve la clé secrète. Mais ma signature ne flag pas?! Après un peu de temps je me rends compte que la signature demandée est sur un message fixe, ok ça flag.
- Vendredi : Je réfléchis à Pain in the Hash. Après l'échec de la Wagner attack j'interprète le problème comme un problème de codes binaires. Pour une parity-check matrix aléatoire $n\times 256$, je veux un mot de code de poids $55$. Il en existe si $n$ est dans les $600$, ce qui correspond aux matrices qu'on peut très facilement inverser, j'ai de l'espoir. Après avoir implémenté l'algo de Stern pour ISD je perds un peu espoir en évaluant les complexités avec les estimateurs ISD. Dans le doute sur la légalité de la chose je n'utilise pas les implems optimisées que je trouve sur internet (même pas sûr que ça aurait suffi). Je ne me sers pas assez du fait que j'ai le droit à plus de $n$ messages au départ.
- Samedi : Je passe la matinée sur Niagara/Black Block, je redécouvre les attaques algébriques et les attaques par corrélation sur LFSR. L'iv de Black Block est incrémenté de 1 à chaque étape, c'est bizarre. Pas convaincu par mon skill en symmétrique, je reviens sur Grabin, l'algorithme de Rabin sur les entiers de Gauss. Je sais extraire des racines mod un complexe premier, je devrais y arriver quand même. Je calcule les erreurs et je vois que je connais les 200 bits les plus forts de p et q. A une cinquantaine près je peux gagner avec Coppersmith. J'essaye de randomiser mes points de départ pour Coppersmith afin de factoriser, mais sans succès.
- Dimanche : Autre chose de prévu le matin, le soir je rentre à la maison et je vais écrire mes write-ups. Je fais quelques memes un peu nuls dans le train puisqu'apparamment c'est encouragé. Je laisse tourner mon script sur Grabin mais je sens qu'il me manque quelque chose. Je stresse tout le weekend que quelqu'un me passe devant en lachant un flag à 21h59 dimanche soir.

Au total j'ai adoré l'expérience, et j'aurais bien aimé avoir eu plus de temps à donner pour essayer aussi les autres domaines. L'événement était très bien géré, bravo !
