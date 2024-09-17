import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    # Query the database to get the user's transactions
    rows = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user_id)

    # Store the portfolio information
    portfolio = []
    total_value = 0

    for row in rows:
        stock = lookup(row["symbol"])
        if stock:
            stock_value = stock["price"] * row["total_shares"]
            total_value += stock_value
            portfolio.append({
                "symbol": row["symbol"],
                "name": stock["name"],
                "shares": row["total_shares"],
                "price": stock["price"],
                "total": stock_value
            })

    # Query user's cash
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Calculate grand total (cash + portfolio)
    grand_total = total_value + user_cash

    return render_template("index.html", portfolio=portfolio, cash=user_cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check if shares is a positive integer
        if not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid number of shares", 400)

        # Lookup stock
        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid stock symbol", 400)

        # Calculate total cost
        cost = stock["price"] * int(shares)

        # Check if user can afford
        user_id = session["user_id"]
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        if cost > user_cash:
            return apology("Can't afford", 400)

        # Update user's cash and insert into transactions
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   user_id, stock["symbol"], int(shares), stock["price"])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]

    # Query transactions for the user
    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ? ORDER BY transacted DESC", user_id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Lookup stock
        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid stock symbol", 400)

        # Render quoted.html with stock information
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=stock["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if username or password is missing
        if not username or not password or not confirmation:
            return apology("Must provide username and password", 400)

        # Check if passwords match
        if password != confirmation:
            return apology("Passwords do not match", 400)

        # Hash the password
        hash_pass = generate_password_hash(password)

        # Try inserting the new user into the database
        try:
            new_user_id = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pass)
        except:
            return apology("Username already exists", 400)

        # Log the user in automatically after registration
        session["user_id"] = new_user_id

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]

    if request.method == "POST":
        # Get form data
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Check for valid input
        if shares <= 0:
            return apology("Invalid number of shares", 400)

        # Lookup stock
        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid stock symbol", 400)

        # Get user's shares for the symbol
        rows = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        if len(rows) == 0 or rows[0]["total_shares"] < shares:
            return apology("Not enough shares", 400)

        # Calculate sale value
        sale_value = stock["price"] * shares

        # Update the database: insert a negative number of shares in transactions, and update the user's cash
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   user_id, symbol, -shares, stock["price"])
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sale_value, user_id)

        return redirect("/")
    else:
        # Query user's stocks
        stocks = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", stocks=stocks)
