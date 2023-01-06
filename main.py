from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps
import forms

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['CKEDITOR_PKG_TYPE'] = 'basic'

ckeditor = CKEditor(app)
Bootstrap(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#configure login manager
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    children = relationship("Comment")




class User(db.Model,UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    children = relationship('BlogPost')

    children = relationship("Comment")


class Comment(db.Model,UserMixin):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    user_name = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    post_parent_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))



db.create_all()

def admin_only(func):
    @wraps(func)
    def wrapper_func(*args , **kwargs):
        try:
            if current_user.id!=1 :
                abort(403)
        except:
            abort(403)
        return func(*args, **kwargs)

    return wrapper_func

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts , loggedin=current_user.is_authenticated)


@app.route('/register',methods=['GET','POST'])
def register():
    form= forms.UserRegisterForm()

    if form.validate_on_submit():
        user = User(
            name = form.name.data,
            email = form.email.data,
            password = generate_password_hash(form.password.data,"pbkdf2:sha256",8)
        )

        query = User.query.filter_by(email=form.email.data).first()

        if query!=None:
            flash('Email already exist, try login instead')
            return redirect(url_for('login'))

        else:

            db.session.add(user)
            db.session.commit()

            login_user(user)

            return redirect(url_for('get_all_posts'))

    return render_template("register.html",form=form)


@app.route('/login', methods=['GET','POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        print(email)
        user = User.query.filter_by(email=email).first()

        if user==None:
            flash('Email doesnot exist')
            return redirect(url_for('login'))

        else:
            password = form.password.data
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))

            else:
                flash('Incorrect password')
                return redirect(url_for('login'))

    return render_template("login.html",form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_parent_id=post_id).all()

    form= forms.CommentForm()

    if form.validate_on_submit() :
        if current_user.is_authenticated:
            comment = Comment(
                text = form.comment.data,
                parent_id = current_user.id,
                post_parent_id = post_id,
                user_name= current_user.name
            )

            db.session.add(comment)
            db.session.commit()

            return redirect(url_for('show_post',post_id=post_id))

        else:
            flash('you need to be logged in to comment')
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, loggedin=current_user.is_authenticated, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html",loggedin=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html",loggedin=current_user.is_authenticated)


@app.route("/new-post",methods=['GET','POST'])
@admin_only
def add_new_post():

        form = CreatePostForm()
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                date=date.today().strftime("%B %d, %Y"),
                parent_id = current_user.id,
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        return render_template("make-post.html", form=form, loggedin=current_user.is_authenticated)




@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,loggedin=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
