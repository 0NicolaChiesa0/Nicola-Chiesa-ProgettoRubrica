
# pip install Flask
# pip install Flask-SQLAlchemy
# pip install Flask-Limiter
# pip install PyJWT

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rubrica.db"
app.config["SECRET_KEY"] = "chiave_segreta"

# limita richieste login
database = SQLAlchemy(app)
limitatore = Limiter(get_remote_address, app=app)

class Contatto(database.Model):
  id        = database.Column(database.Integer, primary_key=True)
  nome      = database.Column(database.String(50))
  cognome   = database.Column(database.String(50))
  email     = database.Column(database.String(50))
  residenza = database.Column(database.String(50))

  # Metodo che trasforma l'oggetto in dizionario JSON
  def dizionario(self):
    return {
      "id": self.id,
      "nome": self.nome,
      "cognome": self.cognome,
      "email": self.email,
      "residenza": self.residenza
    }

class Utente(database.Model):
  id        = database.Column(database.Integer, primary_key=True)
  username  = database.Column(database.String(50), unique=True)
  password  = database.Column(database.String(255))
  nome      = database.Column(database.String(50))
  cognome   = database.Column(database.String(50))
  email     = database.Column(database.String(50))
  residenza = database.Column(database.String(50))

  def dizionario(self):
    return {
      "id": self.id,
      "username": self.username,
      "nome": self.nome,
      "cognome": self.cognome,
      "email": self.email,
      "residenza": self.residenza
    }


# creazione tabelle nel database
with app.app_context():
  database.create_all()

def richiede_token(funzione):
  @wraps(funzione)
  def wrapper(*args, **kwargs):
    intestazione = request.headers.get("Authorization")

    # Controllo se c'è il token
    if not intestazione:
      return jsonify({"errore": "Token mancante"}), 401

    try:
      # Verifica token
      token = intestazione.split(" ")[1]
      jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except:
      return jsonify({"errore": "Token non valido o scaduto"}), 401

    return funzione(*args, **kwargs)

  return wrapper


# -------------------------
# API CONTATTI
# -------------------------

# Endpoint per aggiungere un nuovo contatto
@app.route("/contatti", methods=["POST"])
def aggiungi_contatto():
  dati = request.get_json()

  nuovo = Contatto(
    nome=dati.get("nome"),
    cognome=dati.get("cognome"),
    email=dati.get("email"),
    residenza=dati.get("residenza")
  )

  database.session.add(nuovo)
  database.session.commit()

  return jsonify({"messaggio": "Contatto creato"}), 201


# Endpoint per visualizzare tutti i contatti o uno specifico tramite id
@app.route("/contatti", methods=["GET"])
def visualizza_contatti():
  codice = request.args.get("id")

  # Se passo un id restituisce solo quel contatto
  if codice:
    contatto = database.get_or_404(Contatto, codice)
    return jsonify(contatto.dizionario())

  # restituisce tutta la rubrica
  elenco = Contatto.query.all()
  return jsonify([c.dizionario() for c in elenco])


# Endpoint per eliminare un contatto tramite id
@app.route("/contatti/<int:codice>", methods=["DELETE"])
def elimina_contatto(codice):
  contatto = database.get_or_404(Contatto, codice)
  database.session.delete(contatto)
  database.session.commit()

  return jsonify({"messaggio": "Contatto eliminato"})


# Registrazione nuovo utente
@app.route("/utenti/registrazione", methods=["POST"])
def registra_utente():
  dati = request.get_json()

  # Controllo username (se esiste già)
  if Utente.query.filter_by(username=dati.get("username")).first():
    return jsonify({"errore": "Username già presente"}), 409

  # Salvataggio password criptata
  nuovo_utente = Utente(
    username=dati.get("username"),
    password=generate_password_hash(dati.get("password")),
    nome=dati.get("nome"),
    cognome=dati.get("cognome"),
    email=dati.get("email"),
    residenza=dati.get("residenza")
  )

  database.session.add(nuovo_utente)
  database.session.commit()

  return jsonify({"messaggio": "Utente registrato"}), 201


# Login utente
@app.route("/utenti/login", methods=["POST"])
@limitatore.limit("10 per hour")
def accesso():
  dati = request.get_json()

  utente = Utente.query.filter_by(username=dati.get("username")).first()

  # Controllo credenziali
  if not utente or not check_password_hash(utente.password, dati.get("password")):
    return jsonify({"errore": "Credenziali non valide"}), 401

  # Token valido per 30 minuti
  token = jwt.encode(
    {
      "utente": utente.username,
      "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    },
    app.config["SECRET_KEY"],
    algorithm="HS256"
  )

  return jsonify({"token": token})


# Endpoint protetto che restituisce i dati di un utente
@app.route("/utenti", methods=["GET"])
@richiede_token
def dati_utente():
  username = request.args.get("username")
  utente = Utente.query.filter_by(username=username).first()

  if not utente:
    return jsonify({"errore": "Utente non trovato"}), 404

  return jsonify(utente.dizionario())


# Eliminazione utente (protetta da token)
@app.route("/utenti/<int:codice>", methods=["DELETE"])
@richiede_token
def elimina_utente(codice):
  utente = database.get_or_404(Utente, codice)
  database.session.delete(utente)
  database.session.commit()

  return jsonify({"messaggio": "Utente eliminato"})


# Avvio del server
if __name__ == "__main__":
  app.run(debug=True)