import os
import webapp2
import hashlib
import hmac
import jinja2
import random
import re
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
							   autoescape=True)

secret = 'youcanthackmebro'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val


class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		"""
			stores the user information in the datastore with the user_id cookie
		"""
	
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		"""
			Calls set cookie to revoke the login cookie
		"""
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):

		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)


class MainPage(BlogHandler):
	def get(self):
		self.write('\blog')


def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	"""
	stores password as a hashed value in the datastore
	"""
	if not salt:
		salt = make_salt()

	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	"""
	Validation for password which matches it from datastore
	"""
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group='default'):
	"""
	Creates user key
	"""
	return db.Key.from_path('users', group)


class User(db.Model):
	"""
	Creates user model in the datastore
	"""
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent=users_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return cls(parent=users_key(),
				   name=name,
				   pw_hash=pw_hash,
				   email=email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u
			
def blog_key(name='default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)
	authored = db.TextProperty()
	current_like = db.ListProperty(str)
	likes = db.IntegerProperty(required=True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p=self)

	@property
	def comments(self):
		return Comment.all().filter("post = ", str(self.key().id()))
		
	@classmethod
	def order_post(cls, name):
		u = cls.all().filter('name =', name).get()
		return u

class BlogFront(BlogHandler):
	def get(self):
		posts = greetings = Post.all().order('-created')
		if not self.user:
			self.render('front.html', posts=posts)
		else:
			current_blogger = self.user.name
			self.render('front.html', posts=posts, current_blogger=current_blogger)


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
	def get(self):
		if not self.user:
			self.render("signup-form.html")
		else:
			self.render('signup-form.html', signup_error=signup_error)

	def post(self):
		if not self.user:
			have_error = False
			self.username = self.request.get('username')
			self.password = self.request.get('password')
			self.verify = self.request.get('verify')
			self.email = self.request.get('email')

			params = dict(username=self.username, 
						  email=self.email)

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

			if have_error:
				self.render('signup-form.html', **params)
			else:
				self.done()
		else:
			self.render('signup-form.html', signup_error=signup_error)

	def done(self, *a, **kw):
		raise NotImplementedError

class Comment(db.Model):
	comment = db.StringProperty(required=True)
	post = db.StringProperty(required=True)

	@classmethod
	def render(self):
		self.render("comment.html")

class Register(Signup):
	def done(self):
		"""
			Validation to check if the username exists or not
		"""
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username=msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/blog')


class Login(BlogHandler):
	def get(self):
		if not self.user:
			self.render('login-form.html')
		else:
			self.render('login-form.html', signup_error=signup_error)

	def post(self):
		if not self.user:
			username = self.request.get('username')
			password = self.request.get('password')

			u = User.login(username, password)
			if u:

				self.login(u)
				self.redirect('/blog')
			else:
				msg = 'Invalid login'
				self.render('login-form.html', error=msg)
		else:
			self.render('login-form.html', signup_error=signup_error)


class Logout(BlogHandler):
	def get(self):
		if self.user:
			self.logout()
			self.redirect('/blog')
		else:
			self.write('')

class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return
		if not self.user:
			self.render("permalink.html", post=post)
		else:
			current_blogger = self.user.name
			self.render("permalink.html", post=post, current_blogger=current_blogger)


class MessageEditDelete(BlogHandler):
	"""
		Class which checks if the user has permissions to edit or delete
	"""
	def get(self):
		error_generic = "You don't have permission to delete or edit."
		self.render("error.html", error_generic=error_generic)			
			
class MessageErrorLike(BlogHandler):
	"""
		Checks if the user already liked the post or not
	"""
	def get(self):
		error_generic = "You can only like a post once and you cant like your own."
		self.render("error.html", error_generic=error_generic)

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect('/login')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent=blog_key(), subject=subject, content=content,
					 authored=User.by_name(self.user.name).name, likes=0,
					 current_like=[])

			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
			pid = p.key().id()
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content,
						error=error)


class PostRefresh(BlogHandler):
	def get(self, post_id):
		if not self.user:
			return self.redirect('/login')
		else:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			x = post.authored
			y = self.user.name

			if x == y:
				error="Dont leave subject or content blank"
				key = db.Key.from_path('Post', int(post_id), parent=blog_key())
				post = db.get(key)
				self.render("postrefresh.html", subject=post.subject,
							content=post.content, error=error)


	def post(self, post_id):
		if not self.user:
			return self.redirect("/login")
		else:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			x = post.authored
			y = self.user.name
			
			if x == y:
				subject = self.request.get('subject')
				content = self.request.get('content')
				key = db.Key.from_path('Post', int(post_id), parent=blog_key())
				p = db.get(key)
				p.subject = self.request.get('subject')
				p.content = self.request.get('content')
				p.put()
				self.redirect('/blog/%s' % str(p.key().id()))
				pid = p.key().id()


class LikedBy(BlogHandler):
	def get(self, post_id):
		if not self.user:
			return self.redirect('/login')
		else:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			author = post.authored
			current_user = self.user.name

			if author == current_user or current_user in post.current_like:
				self.redirect('/errorlike')
			else:
				post.likes = post.likes + 1
				post.current_like.append(current_user)
				post.put()
				self.redirect('/')


class RemovePost(BlogHandler):
	def get(self, post_id):
		if not self.user:
			return self.redirect('/login')
		else:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			x = post.authored
			y = self.user.name

			if x == y:
				key = db.Key.from_path('Post', int(post_id), parent=blog_key())
				post = db.get(key)
				post.delete()
				self.render("delete.html")


class NewComment(BlogHandler):
	def get(self, post_id):

		if not self.user:
			error = "You can't comment without logging in"
			self.redirect("/login")
			return
		post = Post.get_by_id(int(post_id), parent=blog_key())
		subject = post.subject
		content = post.content
		self.render("commentlatest.html", subject=subject,
					content=content, pkey=post.key())

	def post(self, post_id):

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if not post:
			self.error(404)
			return
		if not self.user:
			return self.redirect('login')
		comment = self.request.get('comment')
		if comment:
			c = Comment(comment=comment, post=post_id, parent=self.user.key())
			c.put()
			self.redirect('/blog/%s' % str(post_id))
		else:
			error = "Please write a comment"
			self.render("permalink.html", post=post,
						content=content, error=error)


class RefreshComment(BlogHandler):
	def get(self, post_id, comment_id):
		post = Post.get_by_id(int(post_id), parent=blog_key())
		comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
		if comment:
			self.render("refreshcomment.html", subject=post.subject,
						content=post.content, comment=comment.comment)

	def post(self, post_id, comment_id):
		if not self.user:
			error_generic = "please log in first"
			self.render("error.html", error_generic=error_generic)
		comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
		if comment.parent().key().id() == self.user.key().id():
			comment.comment = self.request.get('comment')
			comment.put()
			self.redirect('/blog/%s' % str(post_id))
		else:
			error_generic = "Error"
			self.render("error.html", error_generic=error_generic)


class RemoveComment(BlogHandler):
	def get(self, post_id, comment_id):
		post = Post.get_by_id(int(post_id), parent=blog_key())
		comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
		if comment:
			comment.delete()
			self.redirect('/blog/%s' % str(post_id))

app = webapp2.WSGIApplication([
	('/', BlogFront),
	('/blog/?', BlogFront),
	('/blog/([0-9]+)', PostPage),
	('/blog/newpost', NewPost),
	('/blog/([0-9]+)/updatepost', PostRefresh),
	('/blog/([0-9]+)/newcomment', NewComment),
	('/blog/([0-9]+)/updatecomment/([0-9]+)', RefreshComment),
	('/blog/([0-9]+)/RemoveComment/([0-9]+)', RemoveComment),
	('/blog/([0-9]+)/like', LikedBy),
	('/signup', Register),
	('/blog/([0-9]+)/removepost', RemovePost),
	('/login', Login),
	('/logout', Logout),
	('/errorlike', MessageErrorLike)
], debug=True)
