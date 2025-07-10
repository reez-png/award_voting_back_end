# tests/conftest.py
import pytest
from app import app, db, User, Category, Nominee, AwardSetting, Transaction, AdminLogEntry
import datetime as dt
from datetime import timezone # NEW: Import timezone
import os

@pytest.fixture(scope='function')
def client():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    app.config['PAYSTACK_SECRET_KEY'] = 'test_paystack_secret_key'
    app.config['PAYSTACK_API_BASE_URL'] = 'http://test-paystack-api.com'
    app.config['PAYSTACK_CALLBACK_URL'] = 'http://test.com/callback'
    app.config['PAYSTACK_WEBHOOK_URL'] = 'http://test.com/webhook'
    app.config['BOOTSTRAP_KEY'] = 'test_bootstrap_key'

    with app.app_context():
        db.create_all()
        if not AwardSetting.query.filter_by(key='voting_active').first():
            db.session.add(AwardSetting(key='voting_active', value='true', description='Test setting'))
        if not AwardSetting.query.filter_by(key='show_live_rankings').first():
            db.session.add(AwardSetting(key='show_live_rankings', value='false', description='Test setting'))
        if not AwardSetting.query.filter_by(key='voting_start_time').first():
            # FIX: Use timezone-aware datetime.now(timezone.utc)
            db.session.add(AwardSetting(key='voting_start_time', value=dt.datetime.now(timezone.utc).isoformat(), description='Test setting'))
        if not AwardSetting.query.filter_by(key='voting_end_time').first():
            # FIX: Use timezone-aware datetime.now(timezone.utc)
            future_date = dt.datetime.now(timezone.utc) + dt.timedelta(days=365)
            db.session.add(AwardSetting(key='voting_end_time', value=future_date.isoformat(), description='Test setting'))
        db.session.commit()

        yield app.test_client()

        db.session.remove()
        db.drop_all()