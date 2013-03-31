from application import *

if __name__ == "__main__":

    db.create_all()

    officer_type = UserType("officer")
    admin_rule = Rule("admin", [officer_type])

    db.session.add(officer_type, admin_rule)
    db.session.commit()
