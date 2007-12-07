from turbogears import testutil, database
from signserv.model import Key

database.set_db_uri("sqlite:///:memory:")

class TestKey(testutil.DBTest):

    def get_model(self):
        return Key

    def test_creation(self):
        key = Key(key_id='F5B783C4', name='signserv-test',
                  description='Signing Server (Test key)',
                  email='nobody@fedoraproject.org', passphrase='abcdefg')
        assert key.key_id == 'F5B783C4'
        assert key.name == 'signserv-test'
        assert key.email == 'nobody@fedoraproject.org'
        assert key.passphrase == 'abcdefg'
