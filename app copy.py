from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import uuid
import pandas as pd
from io import BytesIO
from sqlalchemy import or_
from flask_bcrypt import Bcrypt




# -------------------- ENV CONFIG -------------------- #
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'defaultsecret')

DB_USER     = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST     = os.getenv('DB_HOST', 'localhost')
DB_PORT     = os.getenv('DB_PORT', '5432')
DB_NAME     = os.getenv('DB_NAME')
DATABASE_URL = os.getenv('DATABASE_URL')

if DATABASE_URL:
    # Heroku-style URL
    app.config['SQLALCHEMY_DATABASE_URI'] = \
      DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = (
      f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

db       = SQLAlchemy(app)
bcrypt   = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate  = Migrate(app, db)

# -------------------- MODELS -------------------- #
class Company(db.Model):
    __tablename__ = 'company'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(150), nullable=False, unique=True)
    invite_code = db.Column(db.String(50), unique=True)
    users       = db.relationship('User', backref='company', lazy=True)
    tasks       = db.relationship('Task', backref='company', lazy=True)
    projects    = db.relationship('Project', backref='company', lazy=True)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(100), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    role       = db.Column(db.String(20), default='user')  # admin, manager, user
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    # for manager → team
    team_members = db.relationship('User', remote_side=[id], backref='manager')

class Project(db.Model):
    __tablename__ = 'projects'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    # backref 'tasks' added in Task

class Task(db.Model):
    __tablename__ = 'task'
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    status      = db.Column(db.String(50), default='To Do')
    priority    = db.Column(db.String(20), default='Medium')
    deadline    = db.Column(db.Date, nullable=True)
    estimated_hours = db.Column(db.Float)

    # who it’s assigned to
    assigned_to   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_user = db.relationship(
        'User',
        foreign_keys=[assigned_to],
        backref='assigned_tasks'
    )
    # who created it
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator    = db.relationship(
        'User',
        foreign_keys=[user_id],
        backref='created_tasks'
    )

    # company scope
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

    # project link
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=True)
    project    = db.relationship('Project', backref='tasks')

class TimeSheet(db.Model):
    __tablename__ = 'timesheet'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id    = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    date       = db.Column(db.Date, nullable=False)
    hours      = db.Column(db.Float, nullable=False)
    notes      = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='timesheets')
    task = db.relationship('Task', backref='timesheets')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- HELPERS -------------------- #
def generate_invite_code():
    return str(uuid.uuid4())[:8]

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# -------------------- ROUTES -------------------- #
@app.route('/')
def index():
    return render_template('landing.html', logged_in=current_user.is_authenticated)

# -- AUTH --
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(
            request.form['password']
        ).decode('utf-8')
        company_choice = request.form['company_choice']

        if company_choice == "create":
            company_name = request.form['company_name']
            invite_code  = generate_invite_code()
            company = Company(name=company_name, invite_code=invite_code)
            db.session.add(company)
            db.session.flush()
            user = User(
                username=username,
                password=password,
                company_id=company.id,
                role="admin"
            )
        else:
            invite_code = request.form['invite_code']
            company = Company.query.filter_by(invite_code=invite_code).first()
            if not company:
                flash("Invalid invite code", "danger")
                return render_template('register.html')
            user = User(
                username=username,
                password=password,
                company_id=company.id,
                role="user"
            )

        db.session.add(user)
        db.session.commit()
        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(
            username=request.form['username']
        ).first()
        if user and bcrypt.check_password_hash(
            user.password, request.form['password']
        ):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed! Check username & password.', 'danger')

    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    # Find the user by username
    user = User.query.filter_by(username=username).first()

    # Validate password with bcrypt
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "bad credentials"}), 401

    # Create JWT token
    token = create_access_token(identity={
        "user_id": user.id,
        "company_id": user.company_id
    })

    return jsonify({"access_token": token})



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# -- DASHBOARD & TASK CREATION --
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # ---- Create Task (POST) ----
    if request.method == 'POST':
        title       = request.form['title']
        priority    = request.form.get('priority', 'Medium')
        deadline_s  = request.form.get('deadline')
        deadline    = datetime.strptime(deadline_s, "%Y-%m-%d").date() if deadline_s else None
        assigned_to = request.form.get('assigned_to') or None
        project_id  = request.form.get('project_id') or None
        est         = (request.form.get('estimated_hours') or '').strip()

        task = Task(
            title=title,
            priority=priority,
            deadline=deadline,
            assigned_to=int(assigned_to) if assigned_to else None,
            user_id=current_user.id,
            company_id=current_user.company_id,
            project_id=int(project_id) if project_id else None,
            estimated_hours=float(est) if est else None
        )
        db.session.add(task)
        db.session.commit()
        flash("Task created", "success")
        return redirect(url_for('dashboard'))

    # ---- Base query within company ----
    tasks_query = Task.query.filter(Task.company_id == current_user.company_id)

    # ---- Role scoping ----
    if current_user.role == "user":
        tasks_query = tasks_query.filter(
            (Task.user_id == current_user.id) | (Task.assigned_to == current_user.id)
        )
    elif current_user.role == "manager":
        team_ids = [u.id for u in User.query.filter_by(manager_id=current_user.id).all()]
        tasks_query = tasks_query.filter(
            (Task.assigned_to.in_(team_ids + [current_user.id])) | (Task.user_id == current_user.id)
        )

    # ---- URL filters (GET) ----
    def _pdate(s):
        try: return datetime.strptime(s, "%Y-%m-%d").date()
        except: return None

    # simple ones
    status   = request.args.get('status') or ""
    priority = request.args.get('priority') or ""
    if status:   tasks_query = tasks_query.filter(Task.status == status)
    if priority: tasks_query = tasks_query.filter(Task.priority == priority)

    # project
    pid = request.args.get('project_id') or ""
    if pid:
        try: tasks_query = tasks_query.filter(Task.project_id == int(pid))
        except: pass

    # assigned_to
    aid = request.args.get('assigned_to') or ""
    if aid:
        try: tasks_query = tasks_query.filter(Task.assigned_to == int(aid))
        except: pass

    # search across title / project / assignee
    q = (request.args.get('q') or "").strip()
    if q:
        like = f"%{q}%"
        tasks_query = (
            tasks_query
            .outerjoin(User, Task.assigned_user)
            .outerjoin(Project, Task.project)
            .filter(or_(Task.title.ilike(like),
                        User.username.ilike(like),
                        Project.name.ilike(like)))
        )

    # deadline range
    due_from = _pdate(request.args.get('due_from') or "")
    due_to   = _pdate(request.args.get('due_to') or "")
    if due_from and due_to:
        tasks_query = tasks_query.filter(Task.deadline.between(due_from, due_to))
    elif due_from:
        tasks_query = tasks_query.filter(Task.deadline >= due_from)
    elif due_to:
        tasks_query = tasks_query.filter(Task.deadline <= due_to)

    # ---- Fetch & page data for template ----
    tasks    = tasks_query.order_by(Task.deadline.asc().nullslast(), Task.id.desc()).all()
    users    = User.query.filter_by(company_id=current_user.company_id).all()
    projects = Project.query.filter_by(company_id=current_user.company_id).all()

    start_week  = datetime.today().date() - timedelta(days=datetime.today().weekday())
    total_hours = db.session.query(db.func.sum(TimeSheet.hours)).filter(
        TimeSheet.user_id == current_user.id,
        TimeSheet.date >= start_week
    ).scalar() or 0

    return render_template('dashboard.html', tasks=tasks, users=users, projects=projects, total_hours=total_hours)

    # weekly timesheet summary for logged-in user
    start_week  = datetime.utcnow().date() - timedelta(days=datetime.utcnow().weekday())
    total_hours = db.session.query(db.func.sum(TimeSheet.hours)) \
                    .filter(
                      TimeSheet.user_id == current_user.id,
                      TimeSheet.date >= start_week
                    ).scalar() or 0

    return render_template(
        'dashboard.html',
        tasks=tasks,
        users=users,
        projects=projects,
        total_hours=total_hours
    )


# -- TASK OPERATIONS --
@app.route('/update_task_status/<int:task_id>', methods=['POST'])
@login_required
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)

    # permission checks
    if current_user.role == "user" and task.assigned_to != current_user.id:
        abort(403)
    if current_user.role == "manager":
        team_ids = [u.id for u in User.query.filter_by(
            manager_id=current_user.id
        ).all()]
        if task.assigned_to not in team_ids + [current_user.id]:
            abort(403)

    task.status = request.form['status']
    db.session.commit()
    flash("Task status updated", "success")
    return redirect(url_for('dashboard'))


@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)

    # safety: make sure it’s your company’s task
    if task.company_id != current_user.company_id:
        abort(403)

    # users can only delete their own assigned tasks
    if current_user.role == "user" and task.assigned_to != current_user.id:
        abort(403)

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted", "warning")
    return redirect(url_for('dashboard'))


@app.route('/export_tasks')
@login_required
def export_tasks():
    # scope by role...
    if current_user.role == "admin":
        tasks = Task.query.filter_by(
            company_id=current_user.company_id
        ).all()
    elif current_user.role == "manager":
        team_ids = [u.id for u in User.query.filter_by(
            manager_id=current_user.id
        ).all()]
        tasks = Task.query.filter(
            Task.company_id == current_user.company_id,
            Task.assigned_to.in_(team_ids + [current_user.id])
        ).all()
    else:
        tasks = Task.query.filter(
            Task.assigned_to == current_user.id
        ).all()

    data = []
    for t in tasks:
        data.append({
            "Task":     t.title,
            "Project":  t.project.name if t.project else "",
            "Status":   t.status,
            "Priority": t.priority,
            "Deadline": t.deadline.strftime("%Y-%m-%d") if t.deadline else "",
            "Assigned": t.assigned_user.username if t.assigned_user else "—"
        })

    df     = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Tasks')
    output.seek(0)

    return send_file(
        output,
        download_name="tasks.xlsx",
        as_attachment=True
    )


# -- TIMESHEETS --
@app.route('/timer/start', methods=['POST'])
@auth_either
def timer_start():
    actor = current_actor()
    data = request.get_json(force=True)
    task_id = int(data.get('task_id', 0))
    if not _task_accessible_for(actor, task_id):
        return jsonify({"ok": False, "error": "Task not accessible"}), 403

    # Pause any running entry
    existing = _current_running_entry_for(actor)
    now = datetime.utcnow()
    if existing:
        existing.is_running = False
        existing.paused_at = now
        db.session.commit()

    entry = TimeEntry(
        user_id=actor.id,
        task_id=task_id,
        company_id=actor.company_id,
        started_at=now,
        last_ping_at=now,
        is_running=True,
        active_seconds=0
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"ok": True, "entry_id": entry.id, "task_id": task_id,
                    "running": True, "total_seconds": entry.active_seconds})

@app.route('/timer/ping', methods=['POST'])
@auth_either
def timer_ping():
    actor = current_actor()
    data = request.get_json(force=True)
    activity = bool(data.get('activity', False))

    entry = _current_running_entry_for(actor)
    if not entry:
        return jsonify({"ok": True, "running": False})

    now = datetime.utcnow()
    elapsed = (now - entry.last_ping_at).total_seconds()
    credit = min(15, max(0, int(round(elapsed))))
    if activity and credit > 0:
        entry.active_seconds += credit
    entry.last_ping_at = now
    db.session.commit()

    return jsonify({"ok": True, "running": True,
                    "entry_id": entry.id, "task_id": entry.task_id,
                    "total_seconds": entry.active_seconds})

@app.route('/timer/pause', methods=['POST'])
@auth_either
def timer_pause():
    actor = current_actor()
    entry = _current_running_entry_for(actor)
    if not entry:
        return jsonify({"ok": True, "running": False})

    now = datetime.utcnow()
    grace = min(5, int(round((now - entry.last_ping_at).total_seconds())))
    if grace > 0:
        entry.active_seconds += grace

    entry.is_running = False
    entry.paused_at = now
    db.session.commit()

    hours = round(entry.active_seconds / 3600.0, 2)
    if hours > 0:
        ts = TimeSheet(
            user_id=actor.id,
            task_id=entry.task_id,
            date=datetime.utcnow().date(),
            hours=hours,
            notes=f"Auto from timer (session {entry.id})"
        )
        db.session.add(ts)
        db.session.commit()

    return jsonify({"ok": True, "running": False,
                    "total_seconds": entry.active_seconds, "hours_added": hours})

@app.route('/timesheet', methods=['GET', 'POST'])
@login_required
def timesheet():
    tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    if request.method == 'POST':
        log = TimeSheet(
            user_id = current_user.id,
            task_id = request.form['task_id'],
            date    = datetime.strptime(
                        request.form['date'], "%Y-%m-%d"
                      ).date(),
            hours   = float(request.form['hours']),
            notes   = request.form['notes']
        )
        db.session.add(log)
        db.session.commit()
        flash("Time logged", "success")
        return redirect(url_for('timesheet'))

    logs = TimeSheet.query.filter_by(
        user_id=current_user.id
    ).order_by(TimeSheet.date.desc()).all()
    return render_template('timesheet.html', tasks=tasks, logs=logs)


@app.route('/timesheet_edit/<int:log_id>', methods=['GET', 'POST'])
@login_required
def timesheet_edit(log_id):
    log = TimeSheet.query.get_or_404(log_id)
    if log.user_id != current_user.id:
        abort(403)

    tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    if request.method == 'POST':
        log.task_id = request.form['task_id']
        log.date    = datetime.strptime(
                        request.form['date'], "%Y-%m-%d"
                      ).date()
        log.hours   = float(request.form['hours'])
        log.notes   = request.form['notes']
        db.session.commit()
        flash("Log updated", "success")
        return redirect(url_for('timesheet'))

    return render_template(
        'timesheet_edit.html',
        log=log,
        tasks=tasks
    )


@app.route('/timesheet_delete/<int:log_id>')
@login_required
def timesheet_delete(log_id):
    log = TimeSheet.query.get_or_404(log_id)
    if log.user_id != current_user.id:
        abort(403)
    db.session.delete(log)
    db.session.commit()
    flash("Log deleted", "warning")
    return redirect(url_for('timesheet'))


@app.route('/timesheet_report', methods=['GET', 'POST'])
@login_required
@admin_required
def timesheet_report():
    users = User.query.filter_by(company_id=current_user.company_id).all()
    logs  = []
    if request.method == 'POST':
        uid = request.form.get('user_id') or None
        sd  = request.form.get('start_date')
        ed  = request.form.get('end_date')

        query = TimeSheet.query.join(Task).filter(
            Task.company_id == current_user.company_id
        )
        if uid:
            query = query.filter(TimeSheet.user_id == uid)
        if sd and ed:
            query = query.filter(TimeSheet.date.between(sd, ed))

        logs = query.order_by(TimeSheet.date).all()

    return render_template(
        'timesheet_report.html',
        users=users,
        logs=logs,
        selected_user=request.form.get('user_id'),
        start_date=request.form.get('start_date'),
        end_date=request.form.get('end_date')
    )


from io import BytesIO
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import joinedload

@app.route('/export_timesheet', methods=['POST'])
@login_required
@admin_required
def export_timesheet():
    uid = request.form.get('user_id') or None
    sd  = request.form.get('start_date') or None
    ed  = request.form.get('end_date') or None

    # Base query + eager loads so project/user are available without extra queries
    query = (
        TimeSheet.query
        .join(Task)
        .filter(Task.company_id == current_user.company_id)
        .options(
            joinedload(TimeSheet.task).joinedload(Task.project),
            joinedload(TimeSheet.user)
        )
    )

    # user filter (cast to int)
    if uid:
        try:
            query = query.filter(TimeSheet.user_id == int(uid))
        except ValueError:
            pass  # ignore bad ids

    # date filters (parse safely)
    def parse_date(s):
        try:
            return datetime.strptime(s, "%Y-%m-%d").date() if s else None
        except Exception:
            return None

    sd_date = parse_date(sd)
    ed_date = parse_date(ed)

    if sd_date and ed_date:
        query = query.filter(TimeSheet.date.between(sd_date, ed_date))
    elif sd_date:
        query = query.filter(TimeSheet.date >= sd_date)
    elif ed_date:
        query = query.filter(TimeSheet.date <= ed_date)

    logs = query.order_by(TimeSheet.date.asc()).all()

    # Build rows
    data = []
    for log in logs:
        proj_name = log.task.project.name if (log.task and log.task.project) else ""
        est_hours = (
            float(log.task.estimated_hours)
            if (log.task and log.task.estimated_hours is not None)
            else ""
        )
        data.append({
            "Date": log.date.strftime('%Y-%m-%d'),
            "User": log.user.username if log.user else "",
            "Project": proj_name,
            "Task": log.task.title if log.task else "",
            "Estimated Hours": est_hours,
            "Hours Logged": float(log.hours) if log.hours is not None else 0.0,
            "Notes": log.notes or ""
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Timesheet')
    output.seek(0)

    return send_file(
        output,
        download_name="timesheet.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# -- USER MANAGEMENT (Admin) --
@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.filter_by(company_id=current_user.company_id).all()
    managers = User.query.filter_by(company_id=current_user.company_id, role='manager').all()
    company = Company.query.get(current_user.company_id)

    return render_template('manage_users.html', 
                           users=users, 
                           managers=managers, 
                           invite_code=company.invite_code if company else None)


@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    if user.company_id != current_user.company_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('manage_users'))

    # Optional rename
    new_username = (request.form.get('username') or "").strip()
    if new_username and new_username != user.username:
        exists = User.query.filter(User.username == new_username, User.id != user.id).first()
        if exists:
            flash('Username already taken.', 'danger')
            return redirect(url_for('manage_users'))
        user.username = new_username

    # Role change
    new_role = request.form.get('role')
    if new_role:
        user.role = new_role

    # Manager change
    manager_id = request.form.get('manager_id') or None
    user.manager_id = int(manager_id) if manager_id else None

    db.session.commit()
    flash('User updated successfully.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # scope check
    if user.company_id != current_user.company_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('manage_users'))

    # cannot delete self
    if user.id == current_user.id:
        flash("You can't delete your own account.", "warning")
        return redirect(url_for('manage_users'))

    # prevent deleting the last admin of this company
    if user.role == 'admin':
        admin_count = User.query.filter_by(company_id=current_user.company_id, role='admin').count()
        if admin_count <= 1:
            flash("You cannot delete the only admin in the company.", "danger")
            return redirect(url_for('manage_users'))

    # 1) Remove manager links for this user (people who report to them)
    User.query.filter_by(manager_id=user.id).update({'manager_id': None})

    # 2) Unassign tasks assigned to this user
    Task.query.filter_by(company_id=current_user.company_id, assigned_to=user.id).update({'assigned_to': None})

    # 3) Reassign tasks CREATED by this user to the current admin (Task.user_id is NOT nullable)
    Task.query.filter_by(company_id=current_user.company_id, user_id=user.id).update({'user_id': current_user.id})

    # 4) Delete this user's timesheets (timesheet.user_id is NOT nullable)
    for ts in TimeSheet.query.filter_by(user_id=user.id).all():
        db.session.delete(ts)

    # Finally, delete the user
    db.session.delete(user)
    db.session.commit()

    flash("User deleted.", "warning")
    return redirect(url_for('manage_users'))




# -- PROJECT CRUD (Admin) --
@app.route('/projects')
@login_required
@admin_required
def list_projects():
    projects = Project.query.filter_by(company_id=current_user.company_id).all()
    return render_template('projects.html', projects=projects)


@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_project():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash("Project name cannot be empty.", "danger")
            return redirect(url_for('create_project'))

        p = Project(name=name, company_id=current_user.company_id)
        db.session.add(p)
        db.session.commit()
        flash(f'Project "{name}" created.', 'success')
        return redirect(url_for('list_projects'))

    return render_template('create_project.html')


# -- EDIT TASK (now includes project) --
@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)

    # permission checks
    if current_user.role == "user" and task.assigned_to != current_user.id:
        abort(403)
    if current_user.role == "manager":
        team_ids = [u.id for u in User.query.filter_by(
            manager_id=current_user.id
        ).all()]
        if task.assigned_to not in team_ids + [current_user.id]:
            abort(403)

    users    = User.query.filter_by(company_id=current_user.company_id).all()
    projects = Project.query.filter_by(company_id=current_user.company_id).all()

    if request.method == 'POST':
        task.title      = request.form['title']
        task.priority   = request.form['priority']
        dl = request.form.get('deadline', '')
        task.deadline   = (
            datetime.strptime(dl, "%Y-%m-%d").date()
            if dl else None
        )
        task.assigned_to = int(request.form['assigned_to'])
        task.project_id  = request.form.get('project_id') or None

        db.session.commit()
        flash("Task updated successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template(
        'edit_task.html',
        task=task,
        users=users,
        projects=projects
    )

from flask_login import login_required, current_user
# already have:
# from flask_bcrypt import Bcrypt
# bcrypt = Bcrypt(app)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = (request.form.get('current_password') or '').strip()
        new     = (request.form.get('new_password') or '').strip()
        confirm = (request.form.get('confirm_password') or '').strip()

        # 1) Check current password (stored hash is in current_user.password)
        if not bcrypt.check_password_hash(current_user.password, current):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # 2) Basic validations
        if new != confirm:
            flash('New password and confirm password do not match.', 'danger')
            return redirect(url_for('change_password'))
        if len(new) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('change_password'))
        # prevent reusing the same password
        if bcrypt.check_password_hash(current_user.password, new):
            flash('New password cannot be the same as the current password.', 'warning')
            return redirect(url_for('change_password'))

        # 3) Save new password
        current_user.password = bcrypt.generate_password_hash(new).decode('utf-8')
        db.session.commit()

        flash('Password updated successfully. Please log in again.', 'success')
        return redirect(url_for('logout'))

    return render_template('change_password.html')


# -------------------- MAIN ENTRY -------------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

with app.app_context():
    db.create_all()
