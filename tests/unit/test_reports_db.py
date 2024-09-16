from regps.app.api.utils.reports_db import ReportsDB


def test_check_report_status_authorization():
    aid = "jnhh8f7h79nufb97hbw3fieBHJBgg7uhn"
    lei = "j9h7ufehhcWBUTDVWYH98h9bfyaebgGBFfsa3wFf"
    report_1 = "report 1"
    dig_1 = "sha256-moiuhLFBf9afnHJDfaffg4ehgh"
    report_2 = "report 2"
    dig_2 = "sha256-fer4grniuojnfaNHBBcaaUh89h"
    reports_db = ReportsDB()
    reports_db.register_aid(aid, lei)
    reports_db.add_report(aid, dig_1, report_1)
    reports_db.add_report(aid, dig_2, report_2)
    assert reports_db.authorized_to_check_status(aid, dig_1)
    assert reports_db.authorized_to_check_status(aid, dig_2)
    assert len(reports_db.get_reports_for_aid(aid)) == 2
    assert len(reports_db.get_reports_for_lei(aid)) == 2


def test_check_report_status_authorization_2_aids_from_the_same_lei():
    aid_1 = "jnhh8f7h79nufb97hbw3fieBHJBgg7uhn"
    aid_2 = "UNBOUb8dadh98hnansudHD0jndbuh8hnd"
    lei = "j9h7ufehhcWBUTDVWYH98h9bfyaebgGBFfsa3wFf"
    report_1 = "report 1"
    dig_1 = "sha256-moiuhLFBf9afnHJDfaffg4ehgh"
    report_2 = "report 2"
    dig_2 = "sha256-fer4grniuojnfaNHBBcaaUh89h"
    reports_db = ReportsDB()
    reports_db.register_aid(aid_1, lei)
    reports_db.register_aid(aid_2, lei)
    reports_db.add_report(aid_1, dig_1, report_1)
    reports_db.add_report(aid_2, dig_2, report_2)
    assert reports_db.authorized_to_check_status(aid_1, dig_1)
    assert reports_db.authorized_to_check_status(aid_1, dig_2)
    assert reports_db.authorized_to_check_status(aid_2, dig_1)
    assert reports_db.authorized_to_check_status(aid_2, dig_2)
    assert len(reports_db.get_reports_for_aid(aid_1)) == 1
    assert len(reports_db.get_reports_for_aid(aid_2)) == 1
    assert len(reports_db.get_reports_for_lei(aid_1)) == 2
    assert len(reports_db.get_reports_for_lei(aid_2)) == 2


def test_check_report_status_authorization_2_aids_from_different_lei():
    aid_1 = "jnhh8f7h79nufb97hbw3fieBHJBgg7uhn"
    aid_2 = "UNBOUb8dadh98hnansudHD0jndbuh8hnd"
    lei_1 = "j9h7ufehhcWBUTDVWYH98h9bfyaebgGBFfsa3wFf"
    lei_2 = "mOI8hbsah80hihSHFIHh8h3r8hf8h08hfaiffha0"
    report_1 = "report 1"
    dig_1 = "sha256-moiuhLFBf9afnHJDfaffg4ehgh"
    report_2 = "report 2"
    dig_2 = "sha256-fer4grniuojnfaNHBBcaaUh89h"
    reports_db = ReportsDB()
    reports_db.register_aid(aid_1, lei_1)
    reports_db.register_aid(aid_2, lei_2)
    reports_db.add_report(aid_1, dig_1, report_1)
    reports_db.add_report(aid_2, dig_2, report_2)
    assert reports_db.authorized_to_check_status(aid_1, dig_1)
    assert not reports_db.authorized_to_check_status(aid_1, dig_2)
    assert not reports_db.authorized_to_check_status(aid_2, dig_1)
    assert reports_db.authorized_to_check_status(aid_2, dig_2)
    assert len(reports_db.get_reports_for_aid(aid_1)) == 1
    assert len(reports_db.get_reports_for_aid(aid_2)) == 1
    assert len(reports_db.get_reports_for_lei(aid_1)) == 1
    assert len(reports_db.get_reports_for_lei(aid_2)) == 1