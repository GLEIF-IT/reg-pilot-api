from collections import defaultdict


class ReportsDB:
    def __init__(self):
        self.aid_reports = defaultdict(list)
        self.lei_reports = defaultdict(list)
        self.aid_to_lei_mapping = dict()
        self.lei_digests = defaultdict(set)

    def register_aid(self, aid, lei):
        self.aid_to_lei_mapping[aid] = lei

    def add_report(self, aid, dig, report):
        lei = self.aid_to_lei_mapping[aid] or "-"
        self.aid_reports[aid].append(report)
        self.lei_reports[lei].append(report)
        self.lei_digests[lei].add(dig)

    def drop_status(self, aid):
        self.aid_reports[aid] = []
        return True

    def get_reports_for_aid(self, aid):
        return self.aid_reports[aid]

    def get_reports_for_lei(self, aid):
        lei = self.aid_to_lei_mapping[aid] or "-"
        return self.lei_reports[lei]

    def authorized_to_check_status(self, aid, dig):
        lei = self.aid_to_lei_mapping[aid] or "-"
        return dig in self.lei_digests[lei]