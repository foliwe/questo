import  os
from flask import Flask, render_template, request, session, redirect, flash, url_for, g
from database  import  get_db
from werkzeug.security import generate_password_hash, check_password_hash

def create_app():
  app = Flask(__name__)

  app.config['SECRET_KEY'] = os.urandom(24)

  @app.teardown_appcontext
  def close_db(error):
      if hasattr(g, 'sqlite_db'):
          g.sqlite_db.close()


  def current_user():
    user_result = None
    if 'user' in session:
      db = get_db()
      user_cur = db.execute('select id, email, username,  expert, admin, password from users where username= ?', [session['user']])
      user_result = user_cur.fetchone()
    return user_result

  def check_login(x):
    if not x:
      return redirect(url_for('login'))

  @app.route('/')
  def index():
    user = current_user()
    db = get_db()
    quest_cur = db.execute('''select questions.id, questions.question_text, questions.answer_text, askers.username 
                              as askers_name, experts.username 
                              as expert_name from questions 
                              left join users 
                              as askers 
                              on askers.id = questions.asked_by_id 
                              left join users AS experts 
                              on experts.id = questions.expert_id 
                              where answer_text is not null''')

    questions = quest_cur.fetchall()
    return render_template ('index.html', user=user, questions=questions)



  @app.route('/register',methods=['GET', 'POST'])
  def register():
    user = current_user()
    if request.method == 'POST':
      db = get_db()
      existing_user_cur = db.execute('select id from users where email = ?',[request.form['email']])
      existing_user = existing_user_cur.fetchone()
      if existing_user:
        flash('hello')
        return render_template ('register.html',error="Email already Exits")
        
        
      user = request.form['username']
      email = request.form['email']
      hash_password = generate_password_hash(request.form['password'],method='sha256')
      db.execute('insert into users (username, email, password, expert, admin) values(?,?,?,?,? )',[user, email, hash_password, 0, 0])
      db.commit()

      session['user'] = request.form['username']
      return redirect(url_for('index'))

    return render_template ('register.html', user=user)



  @app.route('/login', methods=['GET', 'POST'])
  def login():
    user = current_user()
    error = None
    if request.method == 'POST':
      db = get_db()
      email = request.form['email']
      user_password = request.form['password']
      user_cur = db.execute('select id, email, username,  password from users where email= ?', [email])
      user = user_cur.fetchone()

      if user:
        
        if check_password_hash(user['password'], user_password):
          session['user'] = user['username']
          flash("Login successfully")
          return redirect(url_for('index'))
        else:
          error = "Incorrect Password"
      else:
        error = "Incorrect email"


    return render_template ('login.html', user=user, error=error)




  @app.route('/ask', methods=['GET', 'POST'])
  def ask():
    user = current_user()

    if not user:
      return redirect(url_for('login'))
    
    if user['admin'] ==1 or user['expert'] == 1:
      return redirect(url_for('index'))
      
    db = get_db()
    if request.method == 'POST':
      q_text = request.form['question']
      exp = request.form['expert']
      db.execute('insert into questions (question_text, asked_by_id, expert_id) values (?,?,?)',[q_text, user['id'], exp])
      db.commit()
      return redirect(url_for('index'))


    expert_cur = db.execute('select id, username from users where expert = (?)',[1])
    experts = expert_cur.fetchall()
    return render_template ('ask.html', user=user, experts=experts)



  @app.route('/question/<int:id>')
  def question(id):
    user = current_user()
    db = get_db()
    quest_cur = db.execute('''SELECT questions.question_text, questions.answer_text, askers.username
                            AS askers_name, experts.username as expert_name
                            FROM questions
                            LEFT JOIN users
                            AS askers
                            ON askers.id = questions.asked_by_id
                            LEFT JOIN users AS experts
                            ON experts.id = questions.expert_id
                            WHERE questions.id = ?''',[id])

    question = quest_cur.fetchone()
    return render_template ('question.html', user=user, question=question)



  @app.route('/answer/<int:question_id>', methods=['GET', 'POST'])
  def answer(question_id):
    db = get_db()
    user = current_user()

    if not user:
      return redirect(url_for('login'))

    if user['expert'] !=1:
      return redirect(url_for('index'))

    if request.method == 'POST':
      answer = request.form['answer']
      db.execute('update questions set answer_text = ? where id = ?', [answer, question_id])
      db.commit()
      return redirect(url_for('unanswered'))
    quest_cur = db.execute('select id, question_text from questions where id = ?',[question_id])
    question = quest_cur.fetchone()
    return render_template ('answer.html', user=user, question=question)



  @app.route('/unanswered')
  def unanswered():
    user = current_user()

    if not user:
      return redirect(url_for('login'))

    if user['expert'] !=1:
      return redirect(url_for('index'))
    db = get_db()

    quest = db.execute('select questions.id, questions.question_text, users.username from questions LEFT JOIN users on users.id = questions.asked_by_id where questions.answer_text is null and questions.expert_id = ?',[user['id']])
    unans_quest = quest.fetchall()
    return render_template ('unanswered.html', user=user ,questions=unans_quest)



  @app.route('/users')
  def users():
    user = current_user()

    if not user:
      return redirect(url_for('login'))

    if user['admin'] !=1:
      return redirect(url_for('index'))

    db = get_db()

    all_users = db.execute('select id, email, username,  expert, admin, password from users')
    user_result = all_users.fetchall()
    return render_template ('users.html', user=user, users=user_result)



  @app.route('/promote/<int:user_id>')
  def promote(user_id):
    user = current_user()

    if not user:
      return redirect(url_for('login'))

    if user['admin'] !=1:
      return redirect(url_for('index'))

    db = get_db()
    db.execute('update users set expert = 1 where id = (?)',[user_id])
    db.commit()
    return redirect(url_for('users'))


  @app.route('/logout')
  def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


  return app