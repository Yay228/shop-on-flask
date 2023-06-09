from flask import Flask, render_template, request,redirect
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
db = SQLAlchemy(app)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=True)
    cost = db.Column(db.Integer, nullable=False)



@app.route('/')
def hello_world():
    return render_template('main.html')


@app.route('/shop')
def shop():
    shop = Post.query.all()
    return render_template('shop.html', posts=shop)




@app.route('/create', methods=['POST', 'GET'])
def create():
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']
        cost = request.form['cost']


        post = Post(title=title, cost=cost, text=text)
 
        try:
            db.session.add(post)
            db.session.commit() 
            return redirect('/')
        except:
            return "При добавлении произошла ошибка!"
        
    else:
        return render_template('create.html')




if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
