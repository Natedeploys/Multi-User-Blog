import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# template directory stuff
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret to use with the hashed val
secret = 'fart'


# render the template
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Make a secured hashed val
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# Make sure that the hashed value is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Parent class for all the handlers
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Uses the hashed value to store inside a cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Read secure cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        # if cookie exits and passes check secure val
        # return cookie val
        return cookie_val and check_secure_val(cookie_val)

    # sets a secure cookie user_id = user id from app engine
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Sets the cookie to nothing causing the user to logout
    # sets path=/
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Every request calls initialize
    # Reads a secure cookie called user ID
    # If it is valid sets self.user to that user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# renders our posts
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# page shown at root site
class MainPage(BlogHandler):
    def get(self):
        # self.write("""
        # """)

        self.render("welcome.html")


# user stuff
# Make a string of five letters
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# Takes name, password and optional salt parameter
# Makes salt if it does not exist and hashes.
# This gets stored in a database
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


# Verifies password, makes sure the hash from
# the database matches the entered password hash
# created when the user attempts to login
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# User objecs that will be stored in the database
class User(db.Model):
    name = db.StringProperty(required=True)
    # We store a hash of the password in the database
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # A decorator method that can be run
    # for example user.by_id("23")
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # Looks up at user by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # Creates a new user register
    @classmethod
    def register(cls, name, pw, email=None):
        # Hashes password
        pw_hash = make_pw_hash(name, pw)
        # Creates user object
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    # A decorator method that can be run
    # for example user.login("john")
    @classmethod
    def login(cls, name, pw):
        # looks up user by name
        u = cls.by_name(name)
        # if the name exists and password matches
        if u and valid_pw(name, pw, u.pw_hash):
            # return user
            return u


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# create our post entity
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # create author to appear in each of our posts
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)
    usersliked = db.StringListProperty()
    usersdisliked = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# show the posts in order set
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


# once you create a post you end up here
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

    def post(self, post_id):
        content = self.request.get('content')


# the class that edits our posts
class EditPost(BlogHandler):
    def get(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        query = db.get(key)

        if not query:
            # self.error(404)
            return self.render("error.html")

        # If user is logged in, proceed
        if self.user:
            username = self.user.name
            author = query.author
            # If logged in user name matches the author name
            if author == username:
                # Pass in flag into template
                flag = True
                self.render("editpost.html", query=query, flag=flag)
            else:
                flag = False
                self.render("editpost.html", query=query, flag=flag)
        # Redirect to login
        else:
            return self.redirect("/login")

    # waits for the right event triggers
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        query = db.get(key)

        # If the post does not exist, return error
        if query is None:
            # self.error(404)
            return self.render("error.html")

        subject = self.request.get('subject')
        content = self.request.get('content')

        # if the user is the author then do the below
        username = self.user.name
        author = query.author
        if author == username:
            if "update" in self.request.POST:
                if subject and content:
                    var = Post.get_by_id(int(post_id), parent=blog_key())
                    var.subject = subject
                    var.content = content
                    var.put()
                    return self.redirect('/blog/%s' % str(var.key().id()))
                else:
                    error = "Both subject and content are required fields"
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        error=error)

            if "delete" in self.request.POST:
                if not self.user:
                    return self.redirect('/blog')

                postid = Post.get_by_id(int(post_id), parent=blog_key())
                return self.redirect('/blog/delete-confirmation/%s' %
                                     str(postid.key().id()))

            # trigger cancel changes if it is our user
            if "cancel" in self.request.POST:
                if not self.user:
                    return self.redirect('/blog')

                return self.redirect('/blog/postandcomments/%s' % str(post_id))
        else:
            self.render("error.html")


# Deletes post
class DelConfirmation(BlogHandler):
    def get(self, post_id):
        if post_id:
            if self.user:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                query = db.get(key)
                if query:
                    self.render("delete-confirmation.html", query=query)
                else:
                    self.error(404)
                    return self.render('error.html')
            else:
                return self.redirect("/login")

    def post(self, post_id):

        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            query = db.get(key)

            username = self.user.name
            author = query.author

            if username == author:
                if "delete-post" in self.request.POST:
                    delVal = Post.get_by_id(int(post_id), parent=blog_key())
                    delVal.delete()
                    return self.redirect("/blog")
                if "cancel-delete" in self.request.POST:
                    return self.redirect("/blog")
            else:
                return self.redirect('/blog')
        else:
            return self.redirect('/login')


# creates new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        # get the author name for the post and assign to post
        author = self.user.name
        postid = self.request.get('id')

        if subject and content:
            p = Post(
                parent=blog_key(),
                subject=subject,
                content=content,
                author=author,
                postid=postid)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                error=error,
                author=author,
                postid=postid)


# Comment section
# Make the database table
class Comment(db.Model):
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    postid = db.StringProperty(required=True)

    # Render our individual comment template
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comments.html", p=self)


# Get the original post content
# Key class to render our blog posts
class Comments(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            allcomments = db.GqlQuery("""select * from Comment where
                                      postid = :post_id
                                      order by created asc""",
                                      post_id=post_id)
            # ATTEMPTING TO GET LIKES FOR THIS POST AND RENDER THEM INSIDE THE
            # HTML! DONE
            likes = db.GqlQuery(
                "select likes from Post where postid = :post_id",
                post_id=post_id)

            statuscheck = db.GqlQuery(
                "select * from Comment where postid = :post_id",
                post_id=post_id).get()
            if statuscheck is None:
                statuscheck = "No comments, submit a comment above."
                self.render(
                    "postandcomments.html",
                    post=post,
                    allcomments=allcomments,
                    likes=likes,
                    statuscheck=statuscheck)
            else:
                self.render(
                    "postandcomments.html",
                    post=post,
                    allcomments=allcomments,
                    likes=likes)

        else:
            return self.redirect('/login')

    # Insert into the comments table
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # Get our comments where the post_id is the post we are on
        allcomments = db.GqlQuery("""select * from Comment where
                                  postid = :post_id order by created asc""",
                                  post_id=post_id)

        author = self.user.name
        content = self.request.get('content')

        # check for the right event
        if "insert" in self.request.POST:
            if content:
                c = Comment(
                    post=post.key,
                    content=content,
                    author=author,
                    postid=post_id)
                c.put()
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments)
            else:
                comment_error = True
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    comment_error=comment_error)

        # ATTEMPTING TO INCREASE LIKES IF BUTTON CLICKED
        if "likes" in self.request.POST:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            # ATTEMPTING TO STOP AN AUTHOR LIKING THEIR OWN POST AND A PERSON
            # WHO ALREADY LIKED!
            if post.author != self.user.name and \
               self.user.name not in post.usersliked:
                post.likes = post.likes + 1
                # ADD TO USERSLIKED
                post.usersliked.append(self.user.name)
                if self.user.name in post.usersdisliked:
                    # REMOVE FROM USERSDISLIKED
                    post.usersdisliked.remove(self.user.name)
                # ATTEMPTING TO STORE INSIDE DATABASE
                post.put()
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments)
            elif self.user.name in post.usersliked:
                error = "You cannot like your own post more than once"
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    error=error)
            else:
                error = "You cannot like your own post"
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    error=error)

        if "dislikes" in self.request.POST:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            # ATTEMPTING TO STOP AN AUTHOR DISLIKING THEIR OWN POST
            if post.author != self.user.name and \
               self.user.name not in post.usersdisliked:
                post.likes = post.likes - 1
                # ADD TO USERSDISLIKED
                post.usersdisliked.append(self.user.name)
                if self.user.name in post.usersliked:
                    # REMOVE FROM USERSLIKED
                    post.usersliked.remove(self.user.name)
                # ATTEMPTING TO STORE INSIDE DATABASE
                post.put()
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments)
            elif self.user.name in post.usersdisliked:
                error = "You cannot dislike your own post more than once"
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    error=error)
            else:
                error = "You cannot dislike your own post"
                self.render(
                    "postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    error=error)


# edit comments
class EditComment(BlogHandler):
    def get(self, comment_id):
        # Attempt to get the comment  id
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return self.render("error.html")

        if self.user:
            username = self.user.name
            author = comment.author
        else:
            return self.redirect('/login')

        # If logged in user name matches the author name
        if author == username:
            # Pass in flag into template
            flag = True
            self.render("editcomment.html", comment=comment, flag=flag)
        else:
            flag = False
            self.render("editcomment.html", comment=comment, flag=flag)

    # Use the post method to update
    def post(self, comment_id):
        content = self.request.get('content')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            username = self.user.name
            author = comment.author
        else:
            return self.redirect('/login')

        if username == author:
            if "update" in self.request.POST:
                if content:
                    comment.content = content
                    comment.put()
                    return self.redirect('/blog/')
                else:
                    error = True
                    self.render(
                        "editcomment.html",
                        comment=comment,
                        content=content,
                        error=error)
        else:
            return self.render("error.html")

        # trigger delete comment if it is our user
        if "delete" in self.request.POST:
            if not self.user:
                return self.redirect('/blog')

            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            return self.redirect("/blog/"
                                 "deletecomment/%s" % str(comment.key().id()))

        # trigger cancel changes if it is our user
        if "cancel" in self.request.POST:
            if not self.user:
                return self.redirect('/blog')

            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            postid = comment.postid
            return self.redirect('/blog/postandcomments/%s' % str(postid))


# actually delete the comment
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if not comment:
                self.error(404)
                return self.render("error.html")

            self.render("deletecomment.html", comment=comment)
        else:
            return self.redirect("/login")

    def post(self, comment_id):
        # First get the post_id using the comment_id
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        comment_author = comment.author

        username = self.user.name

        if username == comment_author:
            if "delete-comment" in self.request.POST:
                key = db.Key.from_path('Comment', int(comment_id))
                comment = db.get(key)
                comment.delete()
                return self.redirect("/blog")
            if "cancel-delete" in self.request.POST:
                return self.redirect("/blog")
        else:
            return self.redirect('/blog')


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    # Render the sign up for

    def get(self):
        self.render("signup-form.html")

    # Get all the values of out the request
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # check if all values are valid
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # If have_error is true, we pass in error messages
        if have_error:
            self.render('signup-form.html', **params)
        else:
            # If no error we call self.done
            self.done()

    # Raises an erro but gets overwritten by unit2signup
    def done(self, *a, **kw):
        raise NotImplementedError


# Inherits from signup and overwrites done
class Unit2Signup(Signup):
    # Just redirects to welcome page with username

    def done(self):
        return self.redirect('/unit2/welcome?username=' + self.username)


# Register class inherits from signup
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:  # if it does then pass back the below
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:  # else proceed with the registration
            u = User.register(self.username, self.password, self.email)
            # Store the user object in the database
            u.put()
            # Call login function and set cookie
            self.login(u)
            # Redirect
            return self.redirect('/blog')


# Handles login
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    # Out of the request we get the username
    # and password
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        # If u we call the login function
        if u:
            self.login(u)
            return self.redirect('/blog')
        # If not we render the form invalid
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Error(BlogHandler):
    def get(self):
        self.render('error.html')


class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/login')


# Inherits from bloghandler, does the welcome screen
class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            return self.redirect('/signup')


# routing stuff
class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            return self.redirect('/unit2/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/postandcomments/([0-9]+)', Comments),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ("/blog/delete-confirmation"
                               "/([0-9]+)", DelConfirmation),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/error', Error),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
