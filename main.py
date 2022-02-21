from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

from forms import CreatePostForm
import datetime
from functools import wraps
from flask import abort
from flask_gravatar import Gravatar

from loginUserForm import LoginUserForm
from registerUserForm import RegisterUserForm
from commentForm import CommentForm

from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user current user isnt authenticated or id is not 1 then return abort with 403 error
        if current_user.id != 1 or not current_user.is_authenticated:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # ***************Relationship*************#
    posts = relationship("BlogPost", back_populates="author")  # *
    comments = relationship("Comment", back_populates="comment_author")  # **


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # ***************Relationship*************#
    author = relationship("User", back_populates="posts")  # *
    comments = relationship("Comment", back_populates="parent_post")  # ***


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # ***************Relationship*************#
    comment_author = relationship("User", back_populates="comments")  # **
    parent_post = relationship("BlogPost", back_populates="comments")  # ***


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_user_form = RegisterUserForm()
    if register_user_form.validate_on_submit():
        try:
            new_user = User(email=register_user_form.email.data,
                            password=generate_password_hash(register_user_form.password.data, method='pbkdf2:sha256',
                                                            salt_length=8), name=register_user_form.name.data)
            db.session.add(new_user)
            db.session.commit()
        except exc.IntegrityError:
            db.session.rollback()
            flash("Email is registered already, Please log in.")
            return redirect(url_for('login'))
            # Log in and authenticate user after adding details to database.
        else:
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", register_user_form=register_user_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginUserForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if not user:
            flash("Email is not Registered")
            return redirect(url_for('login', login_form=login_form))
        elif not check_password_hash(user.password, login_form.password.data):
            flash("Password doesnt match")
            return redirect(url_for('login', login_form=login_form))
        else:
            login_user(user, remember=True)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", login_form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(author_id=current_user.id,
                              post_id=post_id,
                              text=comment_form.comment.data)
        db.session.add(new_comment)
        db.session.commit()
    all_comments = Comment.query.all()
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user,all_comments =all_comments )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        x = datetime.datetime.now()
        today = x.strftime("%B, %d %Y")
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            # author=current_user.name,
            date=today)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)




@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
