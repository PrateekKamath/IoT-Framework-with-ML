
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.linear_model import LogisticRegression, Perceptron
from sklearn.tree import DecisionTreeRegressor
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
from sklearn import metrics
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import re
from bs4 import BeautifulSoup
#import whois
import urllib
import urllib.request
from datetime import datetime
from googlesearch import search
import requests


from sklearn.model_selection import train_test_split
from sklearn.mixture import GaussianMixture
from sklearn.linear_model import Perceptron
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn import svm
from sklearn.ensemble import RandomForestRegressor
import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from keras.layers import Input, Dense
from keras.models import Model
from sklearn import metrics
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import KNeighborsClassifier
from sklearn import svm
from sklearn.ensemble import RandomForestRegressor


import time
from sklearn.preprocessing import StandardScaler
from sklearn.utils import shuffle
from sklearn.metrics import confusion_matrix
from sklearn.linear_model import LogisticRegression, Perceptron
from sklearn.tree import DecisionTreeRegressor
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier



class BotnetDetector:
    def __init__(self):
    
        self.model = None
        self.Xtrain = None
        self.Xtest = None
        self.Ytrain = None
        self.Ytest = None
        self.comb1 = None
        self.Output = None


    
    def print_available_models(self):
        print("Available models: LogisticRegression, Perceptron, DecisionTreeRegressor, GaussianNB, KNeighborsClassifier, RandomForestClassifier")

    def _preprocess_data(self):
        comb_std = (self.comb1 - (self.comb1.mean())) / (self.comb1.std())
        scale = StandardScaler()
        scale.fit(self.comb1)
        self.comb1 = scale.transform(self.comb1)
        self.comb_norm = (self.comb1 - (self.comb1.min())) / ((self.comb1.max()) - self.comb1.min())

    def _split_data(self):
        self.Xtrain, self.Xtest, self.Ytrain, self.Ytest = train_test_split(
            self.comb1, self.Output, test_size=0.3, random_state=1
        )

    def train_model(self, dataset, model_name='LogisticRegression'):
        if model_name == 'LogisticRegression':
            self.model = LogisticRegression(solver='lbfgs', max_iter=5000)
        elif model_name == 'Perceptron':
            self.model = Perceptron(eta0=0.2, max_iter=1000, tol=1e-3, verbose=0, early_stopping=True, validation_fraction=0.1)
        elif model_name == 'DecisionTreeRegressor':
            self.model = DecisionTreeRegressor()
        elif model_name == 'GaussianNB':
            self.model = GaussianNB()
        elif model_name == 'KNeighborsClassifier':
            self.model = KNeighborsClassifier()
        elif model_name == 'RandomForestClassifier':
            self.model = RandomForestClassifier()
        else:
            print(f"Unsupported model name: {model_name}")
            return

        # Assuming dataset is a DataFrame with features and labels
        features = dataset.drop('Out', axis=1)
        labels = dataset['Out']
        self.comb1 = features
        self.Output = labels
        self.Xtrain, self.Xtest, self.Ytrain, self.Ytest = train_test_split(
            self.comb1, self.Output, test_size=0.3, random_state=1
        )
        self.model.fit(features, labels)
        print(f"Model {model_name} trained successfully.")

    
    def _preprocess_live_traffic(self, live_traffic):
        preprocessed_live_traffic =""
        return preprocessed_live_traffic

    def _predict_default_model(self, live_traffic):
        if self.model is None:
            print("No model is trained. Please train a model first.")
            return

        
        predictions = self.model.predict(live_traffic)
        return predictions

    def predict_with_model(self, live_traffic, model_name='default'):
        if model_name == 'default':
            return self._predict_default_model(live_traffic)
        else:
            available_models = ['LogisticRegression', 'Perceptron', 'GaussianNB', 'KNeighborsClassifier', 'RandomForestClassifier']
            if model_name not in available_models:
                print(f"Unsupported model name: {model_name}")
                return

            live_traffic_processed = self.preprocess_live_traffic(live_traffic)
            if model_name == 'LogisticRegression':
                model = LogisticRegression(solver='lbfgs', max_iter=1000)
            elif model_name == 'Perceptron':

                model = Perceptron(eta0=0.2, max_iter=1000, tol=1e-3, verbose=0, early_stopping=True, validation_fraction=0.1)
            elif model_name == 'DecisionTreeRegressor':
                model = DecisionTreeRegressor()
            elif model_name == 'GaussianNB':
                model = GaussianNB()
            elif model_name == 'KNeighborsClassifier':
                model = KNeighborsClassifier()
            elif model_name == 'RandomForestClassifier':
                model = RandomForestClassifier()

            predictions = model.predict(live_traffic_processed)
            return predictions

    def evaluate_all_models(self, dataset):
    
      available_models = ['LogisticRegression', 'Perceptron', 'GaussianNB', 'KNeighborsClassifier', 'RandomForestClassifier']
      for model_name in available_models:
          print(f"\nEvaluating {model_name}:")
          self.train_model(dataset=dataset, model_name=model_name)
          self.evaluate_model(model=self.model)


    def evaluate_model(self, model=None):
        if model is None:
            if self.model is None:
                print("No model is trained. Please train a model first.")
                return
            model = self.model

        prediction = model.predict(self.Xtest)
        print("Accuracy Score: ", accuracy_score(prediction, self.Ytest)*100)
        
    



class ArpSpoofDetector:
    def __init__(self):
        self.IP_MAC_PAIRS = {}
        self.ARP_REQ_TABLE = {}
        self.sniff_requests_thread = threading.Thread(target=self.sniff_requests)
        self.sniff_replays_thread = threading.Thread(target=self.sniff_replays)
        self.alarms = []  # To store alarm messages

    def start_detection(self):
        self.sniff_requests_thread.start()
        self.sniff_replays_thread.start()

    def sniff_requests(self):
        sniff(filter='arp', lfilter=self.outgoing_req, prn=self.add_req, iface=conf.iface)

    def sniff_replays(self):
        sniff(filter='arp', lfilter=self.incoming_reply, prn=self.check_arp_header, iface=conf.iface)

    def print_arp(self, pkt):
        if pkt[ARP].op == 1:
            print(pkt[ARP].hwsrc, ' who has ', pkt[ARP].pdst)
        else:
            print(pkt[ARP].psrc, ' is at ', pkt[ARP].hwsrc)

    def incoming_reply(self, pkt):
        return pkt[ARP].psrc != str(get_if_addr(conf.iface)) and pkt[ARP].op == 2

    def outgoing_req(self, pkt):
        return pkt[ARP].psrc == str(get_if_addr(conf.iface)) and pkt[ARP].op == 1

    def add_req(self, pkt):
        self.ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()

    def check_arp_header(self, pkt):
        if not pkt[Ether].src == pkt[ARP].hwsrc or not pkt[Ether].dst == pkt[ARP].hwdst:
            self.alarm('inconsistent ARP message')
        else:
            self.known_traffic(pkt)

    def known_traffic(self, pkt):
        if pkt[ARP].psrc not in self.IP_MAC_PAIRS.keys():
            self.spoof_detection(pkt)
        elif self.IP_MAC_PAIRS[pkt[ARP].psrc] == pkt[ARP].hwsrc:
            pass
        else:
            self.alarm('IP-MAC pair change detected')

    def spoof_detection(self, pkt):
        ip_ = pkt[ARP].psrc
        t = datetime.datetime.now()
        mac = pkt[0][ARP].hwsrc
        if ip_ in self.ARP_REQ_TABLE.keys() and (t - self.ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
            ip = IP(dst=ip_)
            SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
            E = Ether(dst=mac)
            if not srp1(E / ip / SYN, verbose=False, timeout=2):
                self.alarm('No TCP ACK, fake IP-MAC pair')
            else:
                self.IP_MAC_PAIRS[ip_] = pkt[ARP].hwsrc
        else:
            send(ARP(op=1, pdst=ip_), verbose=False)

    def alarm(self, alarm_type):
        message = f'Under Attack {alarm_type}'
        self.alarms.append(message)
        return message

     


        


class DdosAnalysis:
    def __init__(self, csv_path):
        self.df = pd.read_csv(csv_path)
        self.object_col = []


    def display_info(self):
        print(self.df.info())

    def display_description(self):
        print(self.df.describe())

    def plot_null_values(self):
        self.df.isnull().sum().plot.bar()
        plt.title("NULL Values for each column ")
        plt.xlabel("Column names")
        plt.ylabel("Count")
        plt.show()

    def drop_null_rows(self):
        self.df = self.df.dropna()

    def unique_destinations(self):
        uniq_dest = self.df['dst'].unique()
        total_dst = len(uniq_dest)
        print("Total destination : ", total_dst)
        print("Different destination : ", uniq_dest)

    def analyze_traffic(self):
        gp = self.df.groupby('label')['label'].count()
        plt.bar(list(gp.index), list(gp.values), color=['g', 'r'])
        plt.xticks(list(gp.index))
        plt.xlabel("Traffic label")
        plt.ylabel("Count")
        plt.title("Traffic for normal and Malicious traffic")
        plt.show()

    def plot_attack_normal_traffic(self):
        ip_addr = self.df[self.df['label'] == 0].groupby('dst').count()['label'].index
        normal_traffic = self.df.groupby(['dst', 'label']).size().unstack().fillna(0)[0]
        attack_traffic = self.df.groupby(['dst', 'label']).size().unstack().fillna(0)[1]
        plt.barh(ip_addr, normal_traffic, color='g', label='Normal Traffic')
        plt.barh(ip_addr, attack_traffic, color='r', label='Attack Traffic')
        plt.legend()
        plt.xlabel("Count")
        plt.ylabel("Destination IP Addresses")
        plt.title("Attack and Normal traffic ")
        plt.show()

    def process_data(self):
        object_col = list(self.df.select_dtypes(include=['object']).columns)
        object_col = object_col + ['port_no']
        data = self.df.drop(columns=object_col)
        return data

    def separate_by_protocol(self):
      numeric_cols = self.df.select_dtypes(include=['number']).columns
      udp_df = self.df[self.df['Protocol'] == 'UDP'][numeric_cols].drop(columns=self.object_col)
      tcp_df = self.df[self.df['Protocol'] == 'TCP'][numeric_cols].drop(columns=self.object_col)
      icmp_df = self.df[self.df['Protocol'] == 'ICMP'][numeric_cols].drop(columns=self.object_col)
      return udp_df, tcp_df, icmp_df

    def train_gmm(self, train_data, test_data, train_labels, test_labels):
        gmm = GaussianMixture(n_components=2)
        gmm.fit(train_data)
        train_accuracy = metrics.accuracy_score(train_labels, gmm.predict(train_data))
        test_accuracy = metrics.accuracy_score(test_labels, gmm.predict(test_data))
        return train_accuracy, test_accuracy

    def train_perceptron(self, train_data, test_data, train_labels, test_labels):
        model = Perceptron(random_state=1)
        model.fit(train_data, train_labels)
        train_accuracy = model.score(train_data, train_labels)
        test_accuracy = model.score(test_data, test_labels)
        return train_accuracy, test_accuracy

    def train_mlp_classifier(self, train_data, test_data, train_labels, test_labels, hidden_layer_sizes):
        clf = MLPClassifier(hidden_layer_sizes=hidden_layer_sizes, random_state=5, learning_rate_init=0.01)
        clf.fit(train_data, train_labels)
        accuracy = metrics.accuracy_score(clf.predict(test_data), test_labels)
        return accuracy

    def train_knn_classifier(self, train_data, test_data, train_labels, test_labels, n_neighbors=7):
        knn = KNeighborsClassifier(n_neighbors=n_neighbors)
        knn.fit(train_data, train_labels)
        accuracy = knn.score(test_data, test_labels)
        return accuracy

    def train_svm_classifier(self, train_data, test_data, train_labels, test_labels, kernel='poly'):
        clf = svm.SVC(kernel=kernel)
        clf.fit(train_data, train_labels)
        accuracy = metrics.accuracy_score(clf.predict(test_data), test_labels)
        return accuracy

    def train_random_forest_regressor(self, train_data, test_data, train_labels, test_labels):
        rf = RandomForestRegressor()
        rf.fit(train_data, train_labels)
        predictions = rf.predict(test_data)
        accuracy = metrics.accuracy_score(predictions.round(), test_labels)
        return accuracy

    def plot_feature_importance(self, feature_names, importances):
        plt.bar(feature_names, importances)
        plt.xticks(rotation=45)
        plt.title("Feature Importance in deciding class Label")
        plt.xlabel("Feature names")
        plt.ylabel("Importance ")
        plt.show()


class PhishingWebsiteDetection:
    def __init__(self):
        
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net"

    def explore_data(self,data0):
        print(data0.head())
        print("Shape of the dataset:", data0.shape)
        print("Columns of the dataset:", data0.columns)
        print("Information about the dataset:")
        print(data0.info())
        print("Data distribution:")
        data0.hist(bins=50, figsize=(15, 15))
        plt.show()
        print("Correlation heatmap:")
        plt.figure(figsize=(15, 13))
        sns.heatmap(data0.corr())
        plt.show()
        print("Dataset description:")
        print(data0.describe())

    def preprocess_data(self,data0):
        data = data0.drop(['Domain'], axis=1).copy()
        print("Checking for null or missing values:")
        print(data.isnull().sum())
        data = data.sample(frac=1).reset_index(drop=True)
        return data

    def split_data(self, data):
        y = data['Label']
        X = data.drop('Label', axis=1)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)
        return X_train, X_test, y_train, y_test

    def train_decision_tree(self, X_train, X_test, y_train, y_test):
        tree = DecisionTreeClassifier(max_depth=5)
        tree.fit(X_train, y_train)
        y_test_tree = tree.predict(X_test)
        y_train_tree = tree.predict(X_train)
        acc_train_tree = accuracy_score(y_train, y_train_tree)
        acc_test_tree = accuracy_score(y_test, y_test_tree)
        return tree, acc_train_tree, acc_test_tree

    def train_random_forest(self, X_train, X_test, y_train, y_test):
        forest = RandomForestClassifier(max_depth=5)
        forest.fit(X_train, y_train)
        y_test_forest = forest.predict(X_test)
        y_train_forest = forest.predict(X_train)
        acc_train_forest = accuracy_score(y_train, y_train_forest)
        acc_test_forest = accuracy_score(y_test, y_test_forest)
        return forest, acc_train_forest, acc_test_forest

    def train_mlp_classifier(self, X_train, X_test, y_train, y_test):
        mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100, 100, 100]))
        mlp.fit(X_train, y_train)
        y_test_mlp = mlp.predict(X_test)
        y_train_mlp = mlp.predict(X_train)
        acc_train_mlp = accuracy_score(y_train, y_train_mlp)
        acc_test_mlp = accuracy_score(y_test, y_test_mlp)
        return mlp, acc_train_mlp, acc_test_mlp

    def train_xgboost_classifier(self, X_train, X_test, y_train, y_test):
        xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
        xgb.fit(X_train, y_train)
        y_test_xgb = xgb.predict(X_test)
        y_train_xgb = xgb.predict(X_train)
        acc_train_xgb = accuracy_score(y_train, y_train_xgb)
        acc_test_xgb = accuracy_score(y_test, y_test_xgb)
        return xgb, acc_train_xgb, acc_test_xgb

    def train_autoencoder(self, X_train, X_test):
        input_dim = X_train.shape[1]
        encoding_dim = input_dim
        input_layer = Input(shape=(input_dim,))
        encoder = Dense(encoding_dim, activation="relu", activity_regularizer=regularizers.l1(10e-4))(input_layer)
        encoder = Dense(int(encoding_dim), activation="relu")(encoder)
        encoder = Dense(int(encoding_dim - 2), activation="relu")(encoder)
        code = Dense(int(encoding_dim - 4), activation='relu')(encoder)
        decoder = Dense(int(encoding_dim - 2), activation='relu')(code)
        decoder = Dense(int(encoding_dim), activation='relu')(encoder)
        decoder = Dense(input_dim, activation='relu')(decoder)
        autoencoder = Model(inputs=input_layer, outputs=decoder)
        autoencoder.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        history = autoencoder.fit(X_train, X_train, epochs=10, batch_size=64, shuffle=True, validation_split=0.2)
        acc_train_auto = autoencoder.evaluate(X_train, X_train)[1]
        acc_test_auto = autoencoder.evaluate(X_test, X_test)[1]
        return autoencoder, acc_train_auto, acc_test_auto

    def train_svm_classifier(self, X_train, X_test, y_train, y_test):
        svm = SVC(kernel='linear', C=1.0, random_state=12)
        svm.fit(X_train, y_train)
        y_test_svm = svm.predict(X_test)
        y_train_svm = svm.predict(X_train)
        acc_train_svm = accuracy_score(y_train, y_train_svm)
        acc_test_svm = accuracy_score(y_test, y_test_svm)
        return svm, acc_train_svm, acc_test_svm

    def display_results(self, model_name, acc_train, acc_test):
        results = pd.DataFrame({
            'ML Model': [model_name],  # Wrap model_name in a list to create a DataFrame column
            'Train Accuracy': [acc_train],  # Wrap acc_train in a list
            'Test Accuracy': [acc_test],  # Wrap acc_test in a list
        })
        print(results)
        print("Sorting the dataframe on accuracy:")
        print(results.sort_values(by=['Test Accuracy', 'Train Accuracy'], ascending=False))


    def save_xgboost_model(self, model, filename):
        pickle.dump(model, open(filename, "wb"))
        print(f"XGBoost model saved to {filename}")

    def load_xgboost_model(self, filename):
        loaded_model = pickle.load(open(filename, "rb"))
        return loaded_model
    
    def _getDomain(self, url):  
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    def _havingIP(self, url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip

    def _haveAtSign(self, url):
        if "@" in url:
            at = 1    
        else:
            at = 0    
        return at

    def _getLength(self, url):
        if len(url) < 54:
            length = 0            
        else:
            length = 1            
        return length

    def _getDepth(self, url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth + 1
        return depth

    def _redirection(self, url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    def _httpDomain(self, url):
        domain = urlparse(url).netloc
        if 'https' in domain:
            return 1
        else:
            return 0

    def _tinyURL(self, url):
        match = re.search(self.shortening_services, url)
        if match:
            return 1
        else:
            return 0

    def _prefixSuffix(self, url):
        if '-' in urlparse(url).netloc:
            return 1  # phishing
        else:
            return 0  # legitimate

    def _web_traffic(self, url):
        try:
            query = "link:" + url
            backlink_count = len(list(search(query, num=1, stop=1, pause=2)))
        except Exception as e:
            print(f"Error: {e}")
            return 1  # Return 1 if there's an error in fetching backlinks

        if backlink_count > 0:
            return 0  # Phishing
        else:
            return 1  # Legitimate

    def _domainAge(self, domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain / 30) < 6):
                age = 1
            else:
                age = 0
        return age

    def _domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end / 30) < 6):
                end = 0
            else:
                end = 1
        return end

    def _iframe(self, response):
        if response == "":
            return 1
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                return 0
            else:
                return 1

    def _mouseOver(self, response):
        if response == "":
            return 1
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0

    def _rightClick(self, response):
        if response == "":
            return 1
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 0
            else:
                return 1

    def _forwarding(self, response):
        if response == "":
            return 1
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1

    def featureExtraction(self, url):
        features = []
        # Address bar based features (10)
        features.append(self._getDomain(url))
        features.append(self._havingIP(url))
        features.append(self._haveAtSign(url))
        features.append(self._getLength(url))
        features.append(self._getDepth(url))
        features.append(self._redirection(url))
        features.append(self._httpDomain(url))
        features.append(self._tinyURL(url))
        features.append(self._prefixSuffix(url))

        # Domain based features (4)
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        features.append(dns)
        features.append(self._web_traffic(url))
        features.append(1 if dns == 1 else self._domainAge(domain_name))
        features.append(1 if dns == 1 else self._domainEnd(domain_name))

        # HTML & Javascript based features
        try:
            response = requests.get(url)
        except:
            response = ""

        features.append(self._iframe(response))
        features.append(self._mouseOver(response))
        features.append(self._rightClick(response))
        features.append(self._forwarding(response))

        return features

    