from mailbox import MH
from pathlib import Path


class MailboxSystem(object):
    def __init__(self, rootdir, make=True, mailbox=MH):
        self.root = Path(rootdir)
        self.mailbox = mailbox

        if make and not self.root.resolve().exists():
            self.root.mkdir(parents=True)

    def __contains__(self, dir):
        if type(dir) == Path:
            check_dir = dir
        else:
            check_dir = self.root.joinpath(dir)
        if self.check_root(check_dir):
            return check_dir in self.root.iterdir() and check_dir.exists()
        return False

    def check_root(self, dir):
        #  Check to make dir is a sub file/directory of our root
        if type(dir) == Path:
            dir_path = dir
        else:
            dir_path = self.root.joinpath(dir)
        try:
            if dir_path.relative_to(self.root):
                return True
            return False
        except ValueError as e:
            return False
        except Exception as e:
            print(f'Error: {e}')
            return False

    def add(self, user):
        user_path = self.root.joinpath(user)
        if self.check_root(user_path):
            self.mailbox(user_path).close()

    def get(self, user):
        if type(user) == Path:
            user_dir = user
        else:
            user_dir = self.root.joinpath(user)
        if user_dir in self:
            return self.mailbox(user_dir)
