import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

# form validation functions

USER_name = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_password = re.compile(r"^.{3,20}$")
USER_email = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_name.match(username)


def valid_password(password):
    return USER_password.match(password)


def match_pass(password, v_password):
    if password == v_password:
        return True
    else:
        return False


def valid_email(email):
    return USER_email.match(email)


# funtions to set secure cookie value

secret = 'RAW_is_great'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# fuctions to secure passwords

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_secure_pass(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pass(name, password, h):
    salt = h.split(',')[0]
    return h == make_secure_pass(name, password, salt)


def count_likes(blog_value):
    c = db.GqlQuery('SELECT * FROM Likes Where blog=:1', blog_value)
    return c.count()


def count_dislikes(blog_value):
    c = db.GqlQuery('SELECT * FROM Dislikes Where blog=:1', blog_value)
    return c.count()


# Databases
# blogs databse

class Blogs(db.Model):

    user = db.StringProperty(required=True)
    title = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# user database

class User_info(db.Model):

    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()


# likes database

class Likes(db.Model):

    blog = db.StringProperty(required=True)
    user = db.StringProperty(required=True)


# Dislikes database

class Dislikes(db.Model):

    blog = db.StringProperty(required=True)
    user = db.StringProperty(required=True)


# Comments database

class Comments(db.Model):

    blog = db.StringProperty(required=True)
    user = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    commented = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Hadler class

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# class for cookie validation

class Check_cookie(Handler):

    def cookie_validation(self, name_id):
        user = 'Guest'
        link = '/login'
        value = 'Login/signin'
        if name_id:
            user_id = check_secure_val(name_id)
            if user_id:
                user = User_info.get_by_id(int(user_id)).name
                link = '/logout'
                value = 'Logout'
        info = [user, link, value]
        return info


# class for showing blogs

class BLogs(Handler):

    def get(self):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        blogs = \
            db.GqlQuery('SELECT * FROM Blogs ORDER BY created DESC limit 10'
                        )
        self.render('blogs.html', blogs=blogs, user=list[0],
                    link=list[1], login_logout=list[2])


#class for adding blog page
class AddBlogPage(Handler):

    def render_front(
        self,
        list=list,
        title='',
        blog='',
        error='',
        ):
        self.render(
            'newblog.html',
            title=title,
            blog=blog,
            error=error,
            user=list[0],
            link=list[1],
            login_logout=list[2],
            )

    def get(self):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            self.render_front(list)
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get('title')
        blog = self.request.get('blog')
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if title and blog:
            if list[0] != 'Guest':
                b = Blogs(user=list[0], title=title, blog=blog)
                b.put()
                self.redirect('/blogs/%s' % str(b.key().id()))
            else:
                self.redirect('/login')
        else:
            error = 'we need both fields'
            self.render_front(list, title, blog, error)


# for login_page

class LoginHandler(Handler):

    def get(self):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        self.render('login.html', user=list[0], link=list[1],
                    login_logout=list[2])

    def post(self):
        name = self.request.get('username')
        password = self.request.get('pass')
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))

        user = User_info.all().filter('name =', name).get()
        if user and valid_pass(name, password, user.password):
            new_cookie_val = make_secure_val(str(user.key().id()))
            self.response.headers.add_header('Set-Cookie',
                    'name_id=%s; Path=/' % new_cookie_val)
            self.redirect('/blogs')
        else:
            self.render('login.html', error='Invalid Login',
                        user=list[0], link=list[1],
                        login_logout=list[2])


# Redirection to blog Page

class MainHandler(Handler):

    def get(self):
        self.redirect('/blogs')


# for signup_page

class SignupHandler(Handler):

    def get(self):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        self.render('signup.html', user=list[0], link=list[1],
                    login_logout=list[2])

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_re_password = self.request.get('verify')
        user_email = self.request.get('email')

        verify_user_username = valid_username(user_username)
        verify_user_password = valid_password(user_password)
        match_password = match_pass(user_password, user_re_password)
        verify_email = valid_email(user_email)

        error_username = ''
        error_password = ''
        error_verify = ''
        error_email = ''
        flag = True

        if not verify_user_username:
            error_username = 'Not valid username'
            flag = False
        if not verify_user_password:
            error_password = 'Not valid password'
            flag = False
        if not match_password and user_password:
            error_verify = 'password not verified'
            flag = False
        if user_email and not verify_email:
            error_email = 'Not a valid email'
            flag = False

        if flag and User_info.all().filter('name =',
                user_username).get():
            self.render('signup.html', invalid_user='%s already exist'
                        % user_username)
        elif flag:
            a = User_info(name=user_username,
                          password=make_secure_pass(user_username,
                          user_password), email=user_email)
            a.put()
            new_cookie_val = make_secure_val(str(a.key().id()))
            self.response.headers.add_header('Set-Cookie',
                    'name_id=%s; Path=/' % new_cookie_val)
            self.redirect('/Welcome')
        else:
            list = \
                Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                    ))
            self.render(
                'signup.html',
                invalid_user=error_username,
                invalid_pass=error_password,
                not_verified=error_verify,
                invalid_email=error_email,
                user_error=user_username,
                passW=user_password,
                re=user_re_password,
                mail=user_email,
                user=list[0],
                link=list[1],
                login_logout=list[2],
                )


# logout class

class LogoutHandler(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                'name_id=; Path=/')
        self.redirect('/login')


# Welcome class

class WelcomeHandler(Handler):

    def get(self):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            self.render('Welcome.html', name=list[0], user=list[0],
                        link=list[1], login_logout=list[2])
        else:
            self.redirect('/signup')


# class for operation on blog

class OperationHandler(Handler):

    def get(self, post_key):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        blog = Blogs.get_by_id(int(post_key))
        if blog == None:
            self.redirect('/blogs')
        else:
            likes = count_likes(post_key)
            dislikes = count_dislikes(post_key)
            comments = \
                db.GqlQuery('SELECT * FROM Comments Where blog =:1 ORDER BY commented DESC'
                            , post_key)
            time.sleep(0.4)
            self.render(
                'blogpage.html',
                blog=blog,
                likes=likes,
                dislikes=dislikes,
                comments=comments,
                user=list[0],
                link=list[1],
                login_logout=list[2],
                )

    def post(self, key):
        blog = Blogs.get_by_id(int(key))
        if blog == None:
            self.redirect('/blogs')
            return
        edit_post = self.request.get('edit_post')
        like_post_id = self.request.get('like')
        dislike_post_id = self.request.get('dislike')
        comment_post = self.request.get('comment_done')
        edit_comment = self.request.get('edit')
        error = ''
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            check_user = \
                db.GqlQuery('SELECT * FROM Blogs WHERE title=:1 and user=:2'
                            , Blogs.get_by_id(int(key)).title, list[0])
            user_id = \
                check_secure_val(self.request.cookies.get('name_id'))
            if like_post_id:

                if check_user.count() == 0:
                    u = \
                        db.GqlQuery('SELECT * FROM Likes WHERE blog=:1 and user=:2'
                                    , key, user_id)
                    ds = \
                        db.GqlQuery('SELECT * FROM Dislikes WHERE blog=:1 and user=:2'
                                    , key, user_id)
                    if u.count() == 0:
                        l = Likes(blog=key, user=user_id)
                        l.put()
                        if ds.count() != 0:
                            for i in ds:
                                i.delete()
                    else:
                        error = "You Cann't like again"
                else:

                    error = "You Cann't like your own post"
            elif dislike_post_id:

                if check_user.count() == 0:
                    like = \
                        db.GqlQuery('SELECT * FROM Likes WHERE blog=:1 and user=:2'
                                    , key, user_id)
                    u = \
                        db.GqlQuery('SELECT * FROM Dislikes WHERE blog=:1 and user=:2'
                                    , key, user_id)
                    if u.count() == 0:
                        ds = Dislikes(blog=key, user=user_id)
                        ds.put()
                        if like.count() != 0:
                            for i in like:
                                i.delete()
                    else:
                        error = "You Cann't dislike it again"
                else:

                    error = 'You Cann,t dislike your own post'
            elif comment_post:

                comment = self.request.get('comment')
                if comment:
                    c = Comments(blog=key,
                                 user=User_info.get_by_id(int(user_id)).name,
                                 comment=comment)
                    c.put()
                else:
                    error = "NULL field can't be commented"
            elif edit_comment:
                if User_info.get_by_id(int(user_id)).name \
                    == Comments.get_by_id(int(edit_comment)).user:
                    self.redirect('/commentedit/%s' % edit_comment)
                else:
                    error = 'you can only edit your own comment'
            elif edit_post:
                if User_info.get_by_id(int(user_id)).name \
                    == Blogs.get_by_id(int(edit_post)).user:
                    self.redirect('/postedit/%s' % edit_post)
                else:
                    error = 'You can only edit your own post'

            comments = \
                db.GqlQuery('SELECT * FROM Comments Where blog =:1 ORDER BY commented DESC limit 10'
                            , key)
            time.sleep(0.4)
            self.render(
                'blogpage.html',
                comments=comments,
                error=error,
                blog=blog,
                likes=count_likes(key),
                dislikes=count_dislikes(key),
                user=list[0],
                link=list[1],
                login_logout=list[2],
                )
        else:
            self.redirect('/login')

# For Editing Comments
class EditCommentHandler(Handler):

    def get(self, comment_key):
        comment = Comments.get_by_id(int(comment_key))
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            self.render('comment.html', value=comment.comment,
                        user=list[0], link=list[1],
                        login_logout=list[2])
        else:
            self.redirect('/login')

    def post(self, comment_key):
        edit = self.request.get('edit')
        delete = self.request.get('delete')
        cancel = self.request.get('cancel')
        comment = self.request.get('comment')
        u = Comments.get_by_id(int(comment_key))
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            if comment:
                if edit:
                    c = Comments(blog=u.blog, user=u.user,
                                 comment=comment, commented=u.commented)
                    u.delete()
                    c.put()
                elif delete:
                    u.delete()
                time.sleep(0.2)
                self.redirect('/blogpage/%s' % u.blog)
            else:
                self.render('comment.html',
                            error='Comment Should not be NULL',
                            user=list[0], link=list[1],
                            login_logout=list[2])
        else:
            self.redirect('/login')

# for editing posts
class EditPostHandler(Handler):

    def get(self, post_id):
        blog = Blogs.get_by_id(int(post_id))
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        blog_user = Blogs.get_by_id(int(post_id))
        if list[0] != 'Guest' and blog_user != None and list[0] \
            == blog_user.user:
            self.render(
                'editpost.html',
                title=blog.title,
                value=blog.blog,
                user=list[0],
                link=list[1],
                login_logout=list[2],
                )
        else:
            self.redirect('/blogpage/%s' % post_id)

    def post(self, post_id):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        blog_user = Blogs.get_by_id(int(post_id))
        if list[0] != 'Guest' and blog_user != None and list[0] \
            == blog_user.user:
            edit = self.request.get('edit')
            delete = self.request.get('delete')
            cancel = self.request.get('cancel')
            blog = Blogs.get_by_id(int(post_id))
            if edit:
                blog_txt = self.request.get('blog')
                title_txt = self.request.get('title')
                if blog_txt and title_txt:
                    b = Blogs(user=blog.user, title=title_txt,
                              blog=blog_txt, created=blog.created)
                    blog.delete()
                    b.put()
                else:
                    error = 'Both feilds Required'
                    self.render(
                        'editpost.html',
                        error=error,
                        title=blog.title,
                        value=blog.blog,
                        user=list[0],
                        link=list[1],
                        login_logout=list[2],
                        )
                    return
            elif delete:
                blog_user.delete()
            time.sleep(0.2)
            self.redirect('/blogpage/%s' % post_id)
        else:
            self.redirect('/blogs')


# class for addedblogs

class AddedBlog(Handler):

    def get(self, key):
        list = \
            Check_cookie().cookie_validation(self.request.cookies.get('name_id'
                ))
        if list[0] != 'Guest':
            blog = Blogs.get_by_id(int(key))
            self.render('permalink.html', blog=blog, user=list[0],
                        link=list[1], login_logout=list[2])
        else:
            self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', LoginHandler),
    ('/signup', SignupHandler),
    ('/logout', LogoutHandler),
    ('/blogs', BLogs),
    ('/blogs/addblog', AddBlogPage),
    ('/Welcome', WelcomeHandler),
    ('/blogs/([0-9]+)', AddedBlog),
    ('/postedit/([0-9]+)', EditPostHandler),
    ('/commentedit/([0-9]+)', EditCommentHandler),
    ('/blogpage/([0-9]+)', OperationHandler),
    ], debug=True)
