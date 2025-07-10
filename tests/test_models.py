# tests/test_models.py
from app import db, app, User, Category, Nominee, Vote, AwardSetting, Transaction, AdminLogEntry
import datetime as dt

# This test function will automatically receive the 'client' fixture from conftest.py
# However, for model tests, we often just need the db context.
# We'll explicitly use app.app_context() here to ensure we're in the right context
# for database operations, as the 'client' fixture primarily provides the test client.

def test_user_creation(client): # client fixture is available, though not directly used for HTTP here
    with app.app_context(): # Ensure we are in an app context for DB operations
        user = User(username='testuser', email='test@example.com')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()

        retrieved_user = User.query.filter_by(username='testuser').first()
        assert retrieved_user is not None
        assert retrieved_user.email == 'test@example.com'
        assert retrieved_user.check_password('password123')
        assert retrieved_user.role == 'user'
        assert retrieved_user.vote_balance == 0

def test_category_creation(client):
    with app.app_context():
        category = Category(name='Best Movie', description='Best film of the year')
        db.session.add(category)
        db.session.commit()

        retrieved_category = Category.query.filter_by(name='Best Movie').first()
        assert retrieved_category is not None
        assert retrieved_category.description == 'Best film of the year'

def test_nominee_creation(client):
    with app.app_context():
        category = Category(name='Best Actor', description='Male lead performance')
        db.session.add(category)
        db.session.commit()

        nominee = Nominee(name='John Doe', description='Great acting', category_id=category.id)
        db.session.add(nominee)
        db.session.commit()

        retrieved_nominee = Nominee.query.filter_by(name='John Doe').first()
        assert retrieved_nominee is not None
        assert retrieved_nominee.category.name == 'Best Actor'
        assert retrieved_nominee.vote_count == 0

def test_vote_creation(client):
    with app.app_context():
        user = User(username='voter', email='voter@example.com')
        user.set_password('voterpass')
        db.session.add(user)

        category = Category(name='Best Song', description='Song of the year')
        db.session.add(category)
        db.session.commit() # Commit category first to get its ID

        nominee = Nominee(name='Song X', category_id=category.id)
        db.session.add(nominee)
        db.session.commit() # Commit nominee first to get its ID

        vote = Vote(user_id=user.id, nominee_id=nominee.id, category_id=category.id, is_paid_vote=False)
        db.session.add(vote)
        db.session.commit()

        retrieved_vote = Vote.query.filter_by(user_id=user.id, nominee_id=nominee.id).first()
        assert retrieved_vote is not None
        assert retrieved_vote.is_paid_vote == False
        assert retrieved_vote.voter.username == 'voter'
        assert retrieved_vote.nominee.name == 'Song X'

def test_admin_log_entry_creation(client):
    with app.app_context():
        admin_user = User(username='admin_test', email='admin_test@example.com', role='admin')
        admin_user.set_password('adminpass')
        db.session.add(admin_user)
        db.session.commit()

        log_entry = AdminLogEntry(
            admin_id=admin_user.id,
            admin_username=admin_user.username,
            action_type='CREATE',
            resource_type='CATEGORY',
            resource_id=1,
            details='Created new test category'
        )
        db.session.add(log_entry)
        db.session.commit()

        retrieved_log = AdminLogEntry.query.filter_by(admin_username='admin_test').first()
        assert retrieved_log is not None
        assert retrieved_log.action_type == 'CREATE'
        assert retrieved_log.resource_type == 'CATEGORY'