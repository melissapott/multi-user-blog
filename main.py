#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import random
import hashlib
import hmac
import string


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = 'KJjg8670dlk5IG'  # don't leave this here in productin environment

# these are helper functions provided by the instructor and/or covered
# in classroom exercises.  They are used for rendering the html files
# as jinja templates, for RegEx validation of username and email,
# for hashing and securing passwords, and for validating user cookies


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def check_cookie(self):
    # this function returns the user name in the event
    # that there is a valid user cookie, otherwise returns none
    cookie_val = ""
    user_cookie = self.request.cookies.get('username')
    if user_cookie:
        cookie_val = check_secure_val(user_cookie)
    return cookie_val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def validate_username(username):
    # usernames must be unique, so check if it already exists
    if USER_RE.match(username):
        collide = db.GqlQuery(
            "select * from User where username = '%s'" % (username))
        if collide.count() > 0:
            return False
        else:
            return True

PASS_RE = re.compile(r"^.{3,20}$")


def validate_password(password):
    if PASS_RE.match(password):
        return True

EMAIL_RE = re.compile(r"^$|[\S]+@[\S]+.[\S]+$")


def validate_email(email):
    if EMAIL_RE.match(email):
        return True


# the following classes handle webserver requests

class MainHandler(webapp2.RequestHandler):
    # parent of all other handlers - writes out HTML strings to display
    # as web pages

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class BlogMain(MainHandler):
    # displays main page with 10 most recent blog posts.  check_cookie
    # is called to determine if logged-in or logged out menu options
    # should be displayed on the navbar

    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        username = check_cookie(self)
        self.render("main.html", posts=posts, username=check_cookie(self))


class Post(db.Model):
    # this class defines the elements of a blog post, and will pass a blog
    # post to "post.html" to be rendered.  Because comments and likes belong
    # to a particular post, this class will query the datastore for associated
    # likes and comments
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        post_id = self.key().id()
        self._render_text = self.content.replace('\n', '<br>')
        likes = db.GqlQuery(
            "select * from Likes where post_id = '%s'" % (post_id))
        comments = db.GqlQuery(
            "select * from Comment where post_id = '%s' order by created desc"
            % (post_id))
        return render_str("post.html", p=self, post_id=post_id,
                          comments=comments, like_count=likes.count(),
                          comment_count=comments.count())


class Comment(db.Model):
    # this class defines the elements of a comment in the datastore and will
    # pass a comment to "comments.html" to be displayed
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        comment_id = self.key().id()
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comments.html", c=self, comment_id=comment_id)


class Likes(db.Model):
    # this class defines the elements of a like in the datastore, but
    # since likes are only counted, there is no provision for rendering
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)


class User(db.Model):
    # this class defines the elements of a user in the datastore
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()


class NewPost(MainHandler):
    # this class handles requests made for the newpost.html page and is related
    # to adding, editing or deleting a blog post

    def get(self):
        if check_cookie(self):
            # only logged in users allowed, so check the cookie first
            status = self.request.get("status")
            post_id = self.request.get("post_id")
            if post_id:
                # if a post_id already exists, we're going to be editing or
                # deleting a post, so go and get that post from the datastore
                key = db.Key.from_path('Post', int(post_id))
                post = db.get(key)
                subject = post.subject
                content = post.content
                author = post.author
                self.render("newpost.html", username=check_cookie(
                    self), status=status, post_id=post_id, subject=subject,
                    content=content, author=author)
            else:
                self.render("newpost.html", username=check_cookie(self))
        else:
            self.redirect("/login")

    def post(self):
        # handle a post request from newpost.html
        subject = self.request.get('subject')
        content = self.request.get('content')
        status = self.request.get('status')
        post_id = self.request.get('post_id')
        author = check_cookie(self)

        # we are using the same form for add, update, and delete, so check
        # the status variable first to see which action we're going to perform
        # and if it's authorized - only the post's original author is
        # allowed to edit or delete
        if post_id:
            # if a post_id exists already, then go get that post from the
            # datastore - we're going to be editing or deleting
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)

            if status == 'delete' and post.author == author:
                post.delete()
                self.redirect('/thanks')
            elif status == 'edit' and post.author == author:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/thanks')
            else:
                self.redirect('/')
        else:
            # this is going to be a new post, so just make sure that
            # we have both a subject line and post content - already know
            # that the user is logged in.
            if content and subject:
                p = Post(subject=subject, content=content, author=author)
                p.put()
                self.redirect('/%s' % str(p.key().id()))
            else:
                error = "please enter both a subject and some content"
                self.render("newpost.html", subject=subject,
                            content=content, error=error, username=author)


class Permalink(MainHandler):
    # this class gets a specific post from the datastore and displays it
    # on the permalink.html page

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        self.render("permalink.html", post=post, username=check_cookie(self))


class LikeHandler(MainHandler):
    # this class handles requests sent to /like and is used for managing the
    # rules of liking a post and registering likes in the datastore

    def get(self):
        username = check_cookie(self)  # make sure it's a logged in user
        post_id = self.request.get("post_id")
        if username:
            # only one like per user, can't like their own post, so query
            # the datastore to see if a like already exists for this user
            # and that the user isn't the same as the original author
            likes = db.GqlQuery(
                "select * from Likes where username='%s'and post_id='%s'"
                % (username, post_id))
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if likes.count() < 1 and post.author != username:
                # the like is valid, add it to the datastore
                l = Likes(username=username, post_id=post_id)
                l.put()
            self.redirect(self.request.referrer)
        else:
            # the user isn't logged in - send them to the login page
            self.redirect("/login")


class CommentModalHandler(MainHandler):
    # this class handles requests for the comments modal forms, and for
    # managing the rules of managing comments in the datastore

    def get(self):
        # we are using the same form for adding as well as edit and delete, so
        # first check to see if we're getting the appropriate variables in the
        # request string that would indicate a comment already exists, thus
        # we're going to be doing an edit or delete
        username = check_cookie(self)
        post_id = self.request.get("post_id")
        comment_id = self.request.get("comment_id")
        status = self.request.get("status")

        if status:
            # the comment already exists, so get it out of the datastore and
            # pass it to the comment form
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            comment_text = comment.comment
            author = comment.username
            self.render("commentmodal.html", username=username,
                        post_id=post_id, comment_id=comment_id,
                        content=comment_text, author=author, status=status)

        else:
            # this is going to be a new comment, so just render a blank form
            # with only the username and the related post_id loaded into it
            self.render("commentmodal.html",
                        username=username, post_id=post_id)

    def post(self):
        username = self.request.get('username')
        post_id = self.request.get('post_id')
        comment_id = self.request.get('comment_id')
        status = self.request.get('status')
        comment_text = self.request.get('comment')

        # we are using the same form for add, update, and delete, so check the
        # status variable first to see which action we're going to perform and
        # if it's authorized
        if comment_id:
            # this is an edit or delete, so load up the record from the
            # datastore.  the status variable will tell us which to do, and we
            # want to check to make sure that the user is the same as the
            # original commentor.
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if status == 'delete' and comment.username == username:
                comment.delete()
                self.redirect('/thanks')
            elif status == 'edit' and comment.username == username:
                comment.comment = comment_text
                comment.put()
                self.redirect('/thanks')
            else:
                # the user isn't the same as the original author - can't
                # modify.
                self.redirect('/')
        else:
            # this is a new comment - put it in the datastore
            c = Comment(username=username,
                        comment=comment_text, post_id=post_id)
            c.put()
            self.redirect("/thanks")


class ThanksHandler(MainHandler):
    # this class will handle requests to /thanks, which is called when a user
    # has successfully completed an update/add/edit function

    def get(self):
        username = check_cookie(self)
        self.render("thanks.html", username=username)


class SignupHandler(MainHandler):
    # handles requests to /signup

    def get(self):
        # check to see if there's a user cookie, which means the user is
        # logged in...if so, redirect to the welcome page, otherwise render
        # a signup form
        if check_cookie(self):
            self.redirect("/welcome")
        self.render("signup.html")

    def post(self):
        # make sure all the elements received pass validation tests and if so,
        # set a user cookie and put the user into the datastore with a hashed
        # and salted password
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if (validate_username(username) and validate_password(password) and
                validate_email(email) and password == verify):
            username = self.request.get('username')
            new_cookie = make_secure_val(str(username))
            self.response.headers.add_header(
                'Set-Cookie', 'username=%s' % new_cookie)
            password = make_pw_hash(username, password)
            u = User(username=username, password=password, email=email)
            u.put()
            self.redirect("/welcome")
        else:
            # validation checks have failed...reload the form for another try
            self.render("signup.html", user_check=validate_username(username),
                        password_check=validate_password(password),
                        verify=verify, email_check=validate_email(email),
                        password=password, username=username, email=email)


class LoginHandler(MainHandler):
    # handle requests to /login and respond to user login attempts
    error = False

    def get(self):
        self.render("login.html")

    def post(self):
        # see if a record exists in the datastore with the username received.
        # usernames should be unique, but just in case, make a loop through
        # the datastore results
        username = self.request.get("username")
        password = self.request.get("password")
        user = db.GqlQuery(
            "select * from User where username = '%s'" % (username))
        for u in user:
            if u.username == username:
                # if the username matches, run the password through the hash
                # function...if it's good, set a user cookie and redirect to
                # the welcome page
                pw_check = valid_pw(username, password, u.password)
                if pw_check:
                    new_cookie = make_secure_val(str(username))
                    self.response.headers.add_header(
                        'Set-Cookie', 'username=%s' % new_cookie)
                    self.redirect("/welcome")
        error = True
        # username and password hash didn't match...send the user back
        # to the login page with an error message.
        self.render("login.html", error=error)


class WelcomeHandler(MainHandler):
    # handles requests to /welcome when a user had logged in or signed up

    def get(self):
        username = check_cookie(self)
        if username:
            self.render("welcome.html", username=username)
        else:
            self.redirect("/signup")


class LogoutHandler(MainHandler):
    # handles requests to /logout, clear the user cookie and redirect to login

    def get(self):
        self.response.headers.add_header(
            'Set-Cookie', 'username=%s; Path=/' % '')
        self.redirect("/login")


app = webapp2.WSGIApplication([('/', BlogMain),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', Permalink),
                               ('/signup', SignupHandler),
                               ('/welcome', WelcomeHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/like', LikeHandler),
                               ('/commentmodal', CommentModalHandler),
                               ('/thanks', ThanksHandler)
                               ], debug=True)
