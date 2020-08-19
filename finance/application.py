import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response
# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    rows = db.execute("SELECT * FROM info WHERE username=:username;", username=session["user_name"]) # query the info db to get datas
    user_cash = db.execute("SELECT cash FROM users WHERE username = :username", username=session["user_name"]) # to get cash
    session["user_cash"] = user_cash[0]['cash']



    totals = db.execute("SELECT * FROM totals WHERE username=:username;", username=session["user_name"]) # query the total db to get datas
    balance = totals[0]['balance']
    my_cash = totals[0]['my_cash']
   # db.execute("UPDATE users SET cash=:balance WHERE username=:username;", balance=balance, username=session["user_name"])
    return render_template("index.html", rows=rows, balance=usd(balance), my_cash=usd(my_cash))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        my_symbol = request.form.get("symbol")
        my_symbol = my_symbol.upper()
        number = request.form.get("shares")
        share = int(number)
        info = lookup(my_symbol)
        if info == None:
            return apology("Invalid Symbol")
        if share < 1:
            return apology("share number must be one or more!")
        user_cash = db.execute("SELECT cash FROM users WHERE username = :username", username=session["user_name"]) # to get cash
        current_cash = user_cash[0]['cash']

        name = info['name']
        price = info['price']
        symbol = info['symbol']
        # make calculation
        user_balance = db.execute("SELECT * FROM totals WHERE username=:username", username=session["user_name"])
        my_balance = user_balance[0]['balance']
        total = price * share
        if total > my_balance:
            return apology("Not enough Cash")
        rows = db.execute("SELECT * FROM info WHERE username=:username;", username=session["user_name"]) # query the info db to get datas
        flag = False
        my_counter = 0
        for i in range(len(rows)):
            if name in rows[i].values():
                flag = True
                print(i)
                my_counter = i

        db.execute("INSERT INTO history (username, symbol, shares, price) VALUES (:username, :symbol, :shares, :price);",
                        username=session["user_name"], symbol=symbol, shares=str(share), price=usd(price))


        if flag is True:
            old_shares = rows[my_counter]['shares']
            old_price = rows[my_counter]['price']
            old_total = rows[my_counter]['total']
            new_shares = old_shares + share
            new_total = new_shares * price
            db.execute("UPDATE info SET symbol = :symbol, shares = shares + :shares, price = :price, total = total + :total, usd_total=:usd_total WHERE username=:username AND name=:name;",
                        username=session["user_name"], name=name, symbol=symbol, shares=share, price=price, total=total, usd_total=usd(new_total))

        else:
        # put it to info
            db.execute("INSERT INTO info (username, name, symbol, shares, price, total, usd_total) VALUES (:username, :name, :symbol, :shares, :price, :total, :usd_total);",
                        username=session["user_name"], name=name, symbol=symbol, shares=share, price=price, total=total, usd_total=usd(total))


        all_total = db.execute("SELECT SUM(total) AS sum_total FROM info WHERE username=:username;", username=session["user_name"])
        all_total[0]["sum_total"]
        this_row = db.execute("SELECT * FROM info WHERE username=:username AND name=:name;", username=session["user_name"], name=name)

        total = this_row[0]['total']
        #balance = session["user_cash"] - all_total[0]["sum_total"]
        balance = current_cash - all_total[0]["sum_total"]
        my_cash = balance + all_total[0]["sum_total"]

        db.execute("UPDATE totals SET balance=:balance, my_cash=:my_cash WHERE username=:username;", balance=balance, my_cash=my_cash, username=session["user_name"])

        flash('Bought!')
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM history WHERE username=:username", username=session["user_name"])

    return render_template("history.html", rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        new_rows = db.execute("SELECT * FROM info WHERE username=:username;", username=rows[0]["username"]) # query the info db to get datas
        if len(new_rows) > 0:
            row_count = len(new_rows) - 1
            session['company'] = new_rows[row_count]['name']
        #    print('company init name', session['company'])
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]
        # Redirect user to home page
        flash('You were successfully logged in')
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
    """Get stock quote."""
    if request.method == "POST":
        my_symbol = request.form.get("symbol")
        my_symbol = my_symbol.upper()
        info = lookup(my_symbol)
        if info == None:
            return apology("Invalid Symbol")
        name = info['name']
        price = info['price']
        price = usd(price)
        symbol = info['symbol']
        return render_template("quoted.html", name=name, price=price, symbol=symbol)
    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) == 1:
            return apology("username already exists!", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=request.form.get("username"), password=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))
        db.execute("INSERT INTO totals (username, balance, my_cash) VALUES (:username, :balance, :my_cash);",
                        username=request.form.get("username"), balance=10000, my_cash=10000)
        new_rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = new_rows[0]["id"]
        session["user_name"] = new_rows[0]["username"]
        # Redirect user to home page
        flash('Registered!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    rows = db.execute("SELECT * FROM info WHERE username=:username;", username=session["user_name"]) # query the info db to get datas
    if request.method == "POST":
        my_symbol = request.form.get("symbol")
        my_symbol = my_symbol.upper()
        number = request.form.get("shares")
        share = int(number)
        info = lookup(my_symbol)
        print(info)
        if info == None:
            return apology("Invalid Symbol")
        if share < 1:
            return apology("share number must be one or more!")
        name = info['name']
        price = info['price']
        symbol = info['symbol']
        my_total = price * share
        flag = False
        my_counter = 0
        for i in range(len(rows)):
            if name in rows[i].values():
                flag = True
                my_counter = i

        if flag is False:
            return apology("You do not own any shares of that stock!")

        old_total = rows[my_counter]['total']
        old_shares = rows[my_counter]['shares']
        if share > old_shares:
            return apology("You do not own that many shares of the stock")
        old_price = rows[my_counter]['price']
        #total_old_price = old_price * share
        #new_total = old_total - total_old_price
        new_shares = old_shares - share
        new_total = new_shares * price
        db.execute("UPDATE info SET shares = shares - :shares, price = :price, total = :total, usd_total=:usd_total WHERE username=:username AND name=:name;",
                    username=session["user_name"], name=name, shares=share, price=price, total=new_total, usd_total=usd(new_total))


        all_total = db.execute("SELECT SUM(total) AS sum_total FROM info WHERE username=:username;", username=session["user_name"])
        all_total[0]["sum_total"]
        this_row = db.execute("SELECT * FROM info WHERE username=:username AND name=:name;", username=session["user_name"], name=name)

        #balance = session["user_cash"] - all_total[0]["sum_total"]
        totals = db.execute("SELECT * FROM totals WHERE username=:username;", username=session["user_name"]) # query the history db to get datas

        my_money = totals[0]['my_cash']

        balance = totals[0]['balance'] + my_total
        my_cash = balance + all_total[0]["sum_total"]
       # db.execute("UPDATE users SET cash=:balance WHERE username=:username;", balance=balance, username=session["user_name"])
        db.execute("UPDATE totals SET balance=:balance, my_cash=:my_cash WHERE username=:username;", balance=balance, my_cash=my_cash, username=session["user_name"])

        db.execute("UPDATE users SET cash=:cash WHERE username=:username;", cash=my_cash, username=session["user_name"])

        my_share = f'-{str(share)}'
        db.execute("INSERT INTO history (username, symbol, shares, price) VALUES (:username, :symbol, :shares, :price);",
                        username=session["user_name"], symbol=symbol, shares=my_share, price=usd(price))
        flash('Sold!')
        return redirect('/')
    return render_template("sell.html", rows=rows)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
