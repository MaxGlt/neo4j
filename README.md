# Description

Ce projet fournit une série d'instructions pour déployer Neo4j sur un cluster Kubernetes en utilisant Helm. L'objectif est de configurer Neo4j pour qu'il fonctionne sur un environnement de production basé sur Debian 12 avec K3s, tout en gérant les redirections et les accès via un serveur Nginx. Le projet inclut des configurations pour la mise en place de certificats SSL et l'utilisation d'un Service LoadBalancer pour exposer Neo4j.

# Fonctionnalités

- Déploiement de Neo4j sur Kubernetes via Helm.
- Configuration de Kubernetes avec K3s sur Debian 12.
- Gestion des certificats SSL pour sécuriser les communications.
- Intégration avec Nginx pour le proxy inverse.
- Utilisation de Helm pour la configuration, la gestion et la mise à l'échelle de Neo4j.

# Contribution
Les contributions sont les bienvenues ! Si vous avez des suggestions, des améliorations ou des rapports de bogues, n'hésitez pas à ouvrir une issue ou à soumettre une pull request.

# Licence
Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

# Étapes de Mise en Place du Projet Neo4j avec Helm

## Préparation de l'Environnement

### Installation de K3s sur un serveur de production sous Debian 12

Installer la distribution kubernetes k3s de l'editeur Rancher :  

```sh
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
```

### Désactiver Traefik (conflit avec le serveur Nginx utilisé en tant que reverse proxy pour d'autres applications présentes sur le serveur)

Désactiver Traefik :

```sh
sudo k3s server --disable traefik
```

#### Configurer les utilisateurs et permissions

S'assurer que les permissions sont correctement configurées pour accéder au cluster Kubernetes :

```sh
sudo chmod 644 /etc/rancher/k3s/k3s.yaml
```

Création du répertoire `.kube` pour stocker les fichiers de configuration de Kubernetes :

```sh
mkdir .kube
```

### Configuration de Helm

#### Installer Helm

Télécharger et installer Helm :

```sh
curl -fsSL -o get_helm.sh
https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

#### Initialiser un nouveau projet Helm

Créer un nouveau chart Helm pour Neo4j : 

```sh
helm create neo4j
```

#### Configurer Neo4j avec Helm

Créer le namespace neo4j :

```sh
kubectl create namespace neo4j
```

#### Configurer values.yaml

Définir le nombre de réplicas :
```yaml
replicaCount: 3
```
Spécifier l'image de Neo4j :
```yaml
image:
  repository: neo4j
  tag: latest
```

Configurer le service pour utiliser LoadBalancer :
```yaml
service:
  type: LoadBalancer
  port: 7474
```

Définir les ressources (CPU et mémoire) :
```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "500m"
  limits:
    memory: "4Gi"
    cpu: "1"
```
Configurer la persistance des données :
```yaml
persistence:
  enabled: true
  size: 30Gi
```

Définir les paramètres du HPA :
```yaml
hpa:
  enabled: true
  minReplicas: 2
  maxReplicas: 4
  targetCPUUtilizationPercentage: 75
```

#### Créer et configurer les templates Helm

statefulset.yaml pour gérer les réplicas et les configurations des pods :

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ include "neo4j.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    app: {{ include "neo4j.fullname" . }}
spec:
  serviceName: {{ include "neo4j.serviceName" . }}
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ include "neo4j.fullname" . }}
  template:
    metadata:
      namespace: {{ .Release.Namespace }}
      labels:
        app: {{ include "neo4j.fullname" . }}
    spec:
      enableServiceLinks: false
      containers:
      - name: neo4j
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        ports:
        - containerPort: 7474
          name: http
        - containerPort: 7473
          name: https
        - containerPort: 7687
          name: bolt
        resources:
          requests:
            memory: {{ .Values.resources.requests.memory }}
            cpu: {{ .Values.resources.requests.cpu }}
          limits:
            memory: {{ .Values.resources.limits.memory }}
            cpu: {{ .Values.resources.limits.cpu }}
        volumeMounts:
        - mountPath: /conf
          name: config
        - mountPath: /ssl
          name: certs
        - mountPath: /data
          name: data
      volumes:
      - name: config
        configMap:
          name: neo4j-config
      - name: certs
        secret:
          secretName: {{ .Values.neo4j.certificatesSecret }}
          items:
            # Bolt
            - key: tls.key
              path: bolt/tls.key
            - key: tls.crt
              path: bolt/tls.crt
            - key: tls.crt
              path: bolt/trusted/tls.crt
            # HTTPS
            - key: tls.key
              path: https/tls.key
            - key: tls.crt
              path: https/tls.crt
            - key: tls.crt
              path: https/trusted/tls.crt
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: {{ .Values.persistence.size }}
```

service.yaml pour exposer le service Neo4j :
```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "neo4j.fullname" . }}
  labels:
    app: {{ include "neo4j.fullname" . }}
spec:
  type: {{ .Values.service.type }}
  ports:
  - port: 7474
    targetPort: 7474
    protocol: TCP
    name: http
  - port: 7473
    targetPort: 7473
    protocol: TCP
    name: https
  - port: 7687
    targetPort: 7687
    protocol: TCP
    name: bolt
  selector:
    app: {{ include "neo4j.fullname" . }}
```

#### Créer et Gérer les Secrets Kubernetes

Créer un secret Kubernetes pour stocker les certificats :

```sh
kubectl create secret generic neo4j-certs \
  --from-file=tls.key=/path/to/tls.key \
  --from-file=tls.crt=/path/to/tls.crt
```

#### Déploiement du Chart Helm

Exporter le fichier de configuration de kubernetes afin que helm puisse discuter avec l'api de kubernetes

```sh
kubectl config view  --raw >.kube/config
```

Utiliser Helm pour déployer le chart dans le namespace spécifique :

```sh
helm install neo4j ./neo4j -n neo4j
```

Vérifier que les ressources sont correctement créées et configurées :

```sh
kubectl get all -n neo4j
```
### Finalisation et Tests

Accéder à Neo4j :

Utiliser le domaine configuré pour accéder à l'interface Neo4j via un navigateur ou curl :
```sh
curl -k https://neo4j.local:7473
```

Tester la configuration :

Vérifier que Neo4j fonctionne correctement et que les réplicas s'ajustent si le HPA est activé.
Utiliser le client Neo4j pour se connecter :
```sh
cypher-shell -u neo4j -p <password> -a bolt+s://neo4j.local
```
## Rapport des Erreurs et Résolutions

### Contexte

J'ai déployé Neo4j à l'aide de Kubernetes et Helm sur un serveur sous Debian. Le service est sécurisé avec des certificats SSL et accessible via un serveur Nginx.

### Erreurs Rencontrées et Résolutions

#### Erreur 1 : Problème de Connexion à Neo4j via l'Interface Web

- Symptôme: Lorsque j'accédais à l'interface Neo4j, la connexion échouait.

- Cause : Le problème était lié à la configuration des services Kubernetes utilisant des NodePorts, rendant difficile la gestion des ports spécifiques pour Neo4j, en particulier pour Bolt (port 7687).

#### Résolution

- Service LoadBalancer: J'ai utilisé un service de type LoadBalancer pour exposer les ports nécessaires (7687 pour Bolt, 7474 pour HTTP, 7473 pour HTTPS).

J'ai configuré le service Kubernetes pour utiliser un LoadBalancer :
```yaml
apiVersion: v1
kind: Service
metadata:
  name: neo4j-db-public
spec:
  type: LoadBalancer
  ports:
    - port: 7687
      targetPort: 7687
      name: bolt
    - port: 7474
      targetPort: 7474
      name: http
    - port: 7473
      targetPort: 7473
      name: https
  selector:
    app: neo4j
```
#### Erreur 2: Conflit de Chemins dans la Configuration Nginx

- Symptôme : Lors de la vérification de la configuration Nginx avec la commande `nginx -t`, une erreur indiquait un conflit de chemins (duplicate location "/").
- Cause: Deux blocs `location /` étaient définis dans la configuration Nginx, causant un conflit.

#### Résolution

J'ai utilisé des chemins spécifiques pour les différentes interfaces de Neo4j (HTTP, HTTPS et Bolt).

J'ai mis à jour la configuration Nginx pour éviter le conflit :

```nginx
server {
    listen 80;
    listen [::]:80;

    server_name neo4j.local;
    server_tokens off;

    location / {
       return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name neo4j.local;

    # Certificates
    ssl_certificate /etc/ssl/certs/neo4j/cert.crt;
    ssl_certificate_key /etc/ssl/private/neo4j/key.key;

    # Main location for Neo4j HTTP and HTTPS
    location / {
        proxy_pass http://<LoadBalancer-IP>:7474;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Specific location for Bolt protocol
    location /bolt {
        proxy_pass http://<LoadBalancer-IP>:7687;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Nginx logs
    access_log /var/log/nginx/neo4j.local-access.log;
    error_log /var/log/nginx/neo4j.local-error.log;

    # TLS protocols
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
}
```

#### Erreur 3: Utilisation Incorrecte des Certificats SSL dans Neo4j

- Symptôme: Neo4j ne démarrait pas correctement avec les certificats SSL, causant des erreurs de connexion sécurisée.
- Cause: Les chemins vers les certificats SSL dans la configuration Neo4j étaient incorrects.

#### Résolution

- J'ai mis à jour le ConfigMap pour inclure les chemins corrects vers les certificats SSL.
- J'ai activé l'authentification et ajusté les configurations SSL pour les connecteurs Bolt et HTTPS.

##### ConfigMap Mis à Jour

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: neo4j-config
data:
  neo4j.conf: |
    # Accept non-local connections
    server.default_listen_address=0.0.0.0

    # Security
    dbms.security.auth_enabled=true

    # Bolt connector
    server.bolt.enabled=true
    server.bolt.tls_level=OPTIONAL
    server.bolt.listen_address=:7687

    # Bolt SSL configuration
    dbms.ssl.policy.bolt.enabled=true
    dbms.ssl.policy.bolt.base_directory=/ssl/bolt
    dbms.ssl.policy.bolt.private_key=/ssl/bolt/tls.key
    dbms.ssl.policy.bolt.public_certificate=/ssl/bolt/tls.crt
    # ssl.policy.bolt.client_auth : NONE, OPTIONAL, REQUIRED
    dbms.ssl.policy.bolt.client_auth=OPTIONAL

    # HTTP connector
    server.http.enabled=true
    server.http.listen_address=:7474

    # HTTPS connector
    server.https.enabled=true
    server.https.listen_address=:7473

    # HTTPS SSL configuration
    dbms.ssl.policy.https.enabled=true
    dbms.ssl.policy.https.base_directory=/ssl/https
    dbms.ssl.policy.https.private_key=/ssl/https/tls.key
    dbms.ssl.policy.https.public_certificate=/ssl/https/tls.crt
    # ssl.policy.https.client_auth : NONE, OPTIONAL, REQUIRED
    dbms.ssl.policy.https.client_auth=OPTIONAL

    # Additional security settings
    dbms.security.procedures.unrestricted=apoc.*,algo.*
    dbms.security.procedures.allowlist=apoc.*,algo.*
```

### Conclusion
Ces résolutions m'ont permis de sécuriser et de stabiliser mon déploiement Neo4j avec Kubernetes et Nginx. En appliquant ces modifications, j'ai pu surmonter les problèmes initiaux et garantir une configuration sécurisée et fonctionnelle de Neo4j.