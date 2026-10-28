import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "app" / "routers" / "multiguard_remote.py"


class WorkshopRemoteButtonsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = SOURCE.read_text(encoding="utf-8")
        cls.ui = src[src.index("def owner_workshop_workspace("):src.index('@router.post("/panel/remote-api/workshop/request/', src.index("def owner_workshop_workspace("))]
        cls.active = src[src.index("def panel_workshop_active("):src.index('@router.get("/panel/remote/workshop/',src.index("def panel_workshop_active("))]
        cls.status = src[src.index("def panel_workshop_status("):src.index('@router.post("/panel/remote-api/workshop/sessions/', src.index("def panel_workshop_status("))]

    def test_paid_pro_uses_client_consent_share_not_service_pro(self):
        source = SOURCE.read_text(encoding="utf-8")
        commercial = source.split('@router.post("/agent/remote/mesh-enroll")', 1)[1].split('@router.post("/agent/remote/poll")', 1)[0]
        self.assertIn("_has_active_remote_pro(installation,", commercial)
        self.assertIn("single_prompt=(os.getenv(", commercial)
        self.assertNotIn("SERVICE_PRO", commercial)
        self.assertIn("meshcentral.create_client_approved_share(", source)
        self.assertIn("str(session_uuid)", source)

    def test_single_prompt_is_explicit_opt_in_and_legacy_stays_default(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED") == "1"', source)
        mesh = (SOURCE.parent / "multiguard_meshcentral.py").read_text(encoding="utf-8")
        self.assertIn('if os.getenv("MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED", "") != "1":', mesh)
        self.assertIn("return create_share(node_id, session_label, capabilities, duration_minutes)", mesh)
        self.assertIn("single_prompt=True", mesh)

    def test_explicit_consent_endpoint_is_separate_from_unattended(self):
        source = SOURCE.read_text(encoding="utf-8")
        consent_route = source.split('@router.post("/panel/remote-api/workshop/request-consent/{installation_id}")', 1)[1].split('@router.post("/panel/remote-api/workshop/request/{installation_id}")', 1)[0]
        unattended_route = source.split('@router.post("/panel/remote-api/workshop/request/{installation_id}")', 1)[1].split('@router.get("/panel/remote-api/workshop/sessions/', 1)[0]
        self.assertIn("workshop.request_consent_for_owner(installation_id)", consent_route)
        self.assertNotIn("request_for_owner(installation_id)", consent_route)
        self.assertIn("workshop.request_for_owner(installation_id)", unattended_route)
        self.assertIn("Depends(_owner_panel_csrf)", consent_route)

    def test_service_pro_has_distinct_consent_and_standing_buttons(self):
        self.assertIn('id="ws-consent" disabled hidden', self.ui)
        self.assertIn("const consent = document.getElementById('ws-consent');", self.ui)
        self.assertIn("consent.onclick = async () => {", self.ui)
        self.assertIn("api('request-consent/' + installation, 'POST')", self.ui)
        self.assertIn("api('request/' + installation, 'POST')", self.ui)
        self.assertIn("consent.disabled = true;", self.ui)
        self.assertIn("consent.disabled = !customerMode;", self.ui)

    def test_accepted_workshop_consent_has_separate_ten_minute_connection_window(self):
        workshop = (SOURCE.parent / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
        decision = workshop.split("def workshop_remote_decision(", 1)[1].split("\n@router.", 1)[0]
        self.assertIn('"consent_expires":consented_at+timedelta(minutes=10)', decision)
        self.assertIn("SET status='CONSENTED',consented_at=:now", decision)
        self.assertIn("if row[\"expires_at\"]<_now():", decision)
        self.assertNotIn('"consent_expires":consented_at+timedelta(minutes=5)', decision)

    def test_customer_assignment_revokes_unattended_before_licence_switch(self):
        licence = (SOURCE.parent / "multiguard_license.py").read_text(encoding="utf-8")
        self.assertIn("workshop.close_before_rights_change(connection,installation_id)", licence)
        self.assertIn("workshop.close_before_rights_change(con,installation_id)", licence)
        workshop = (SOURCE.parent / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
        close = workshop.split("def close_before_rights_change(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("_open(db, iid, entitlement_lost=True)", close)
        self.assertIn('invalidate_standing_authorization(db,iid,"SERVICE_RIGHTS_CHANGED")', close)

    def test_release_requires_unactivated_licence_state(self):
        licence = (SOURCE.parent / "multiguard_license.py").read_text(encoding="utf-8")
        release = licence.split("def approve_reception_license(", 1)[1].split("\n@router.", 1)[0]
        self.assertIn("lifecycle IN ('UNASSIGNED','SERVICE_TEST','PENDING_ACCEPTANCE')", release)
        self.assertIn("approved_at=COALESCE(approved_at,now())", release)
        self.assertIn("AND accepted_at IS NULL AND valid_from IS NULL AND valid_until IS NULL", release)
        self.assertIn("SET lifecycle='PENDING_ACCEPTANCE'", release)

    def test_acceptance_is_guarded_against_concurrent_licence_change(self):
        licence = (SOURCE.parent / "multiguard_license.py").read_text(encoding="utf-8")
        acceptance = licence.split("def acceptance(req: AcceptanceRequest):", 1)[1].split("\n@router.", 1)[0]
        self.assertIn("WHERE id=:id AND lifecycle='PENDING_ACCEPTANCE'", acceptance)
        self.assertIn("if row is None:", acceptance)
        self.assertIn('raise HTTPException(409, "Licencja zmieniła stan podczas akceptacji; odśwież dane.")', acceptance)

    def test_paid_licence_starts_only_after_acceptance(self):
        licence = (SOURCE.parent / "multiguard_license.py").read_text(encoding="utf-8")
        acceptance = licence.split("def acceptance(req: AcceptanceRequest):", 1)[1].split("\n@router.", 1)[0]
        self.assertIn('if link["lifecycle"] != "PENDING_ACCEPTANCE":', acceptance)
        self.assertIn("valid_from=:started", acceptance)
        self.assertIn("accepted_at=:started", acceptance)
        self.assertIn("valid_until=:valid_until", acceptance)

    def test_workshop_customer_consent_window_is_ten_minutes(self):
        workshop = (SOURCE.parent / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
        request = workshop.split("def request_consent_for_owner(", 1)[1].split("\n@router.post(", 1)[0]
        self.assertIn('"expires": now + timedelta(minutes=10)', request)
        self.assertNotIn('"expires": now + timedelta(minutes=5)', request)
        self.assertIn("'REQUESTED'", request)

    def test_service_pro_reconnect_never_falls_back_to_client_consent(self):
        workshop = (SOURCE.parent / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
        start = workshop.split("def request_for_owner(", 1)[1].split("\n@router.", 1)[0]
        self.assertIn("meshcentral.verify_service_pro_node(node)", start)
        self.assertIn("if not _eligible(grant)", start)
        self.assertNotIn("standing_authorization_record_valid(", start)
        self.assertNotIn("request_consent_for_owner(", start)
        connect = workshop.split("def connect_for_owner(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('"STANDING_SERVICE"', connect)
        self.assertIn("meshcentral.verify_service_pro_node(", connect)
        self.assertIn("meshcentral.create_standing_service_share(", connect)
        self.assertIn("meshcentral.create_client_approved_share(", connect)
        self.assertNotIn("standing_authorization_record_valid(", connect)
        self.assertIn("meshcentral.revoke_share(node,previous)", connect)
        self.assertIn("if scope is not None else", connect)
        self.assertIn("state.unattendedReady === true", self.ui)
        self.assertIn("state.mode === 'SERVICE_PRO'", self.ui)
        self.assertIn("start.hidden = state.mode !== 'SERVICE_PRO';", self.ui)
        self.assertIn("consent.hidden = !customerMode;", self.ui)
        self.assertIn("if (!standingEligible)", self.ui)

    def test_pending_session_blocks_second_consent_request(self):
        self.assertIn("consent.disabled = true;", self.ui)
        self.assertIn("status.textContent = 'Oczekiwanie na decyzję klienta lub przygotowanie sesji…';", self.ui)
        self.assertIn("start.disabled = true;", self.ui)
        self.assertIn("connect.disabled = true;", self.ui)

    def test_viewer_opens_after_verified_binding_without_second_owner_click(self):
        self.assertIn("viewerTab = window.open('about:blank','_blank');", self.ui)
        self.assertIn("if (ready && autoOpen && !opening)", self.ui)
        self.assertIn("await openDesktop();", self.ui)
        self.assertIn("api('sessions/' + connectingSession + '/connect','POST')", self.ui)
        self.assertIn("url.hostname !== 'mesh.multi-servis.pl'", self.ui)
        self.assertIn("if (viewerTab && !viewerTab.closed) viewerTab.close();", self.ui)

    def test_owner_guest_link_opts_into_meshcentral_auto_connect_only_after_url_validation(self):
        marker = "url.searchParams.set('mgautoconnect', '1');"
        self.assertIn(marker, self.ui)
        self.assertLess(self.ui.index("url.hostname !== 'mesh.multi-servis.pl'"), self.ui.index(marker))
        self.assertLess(self.ui.index(marker), self.ui.index("tab.location.replace(url.href)"))

    def test_auto_open_error_is_not_overwritten_by_ready_message(self):
        self.assertIn("if (ready && autoOpen && !opening)", self.ui)
        self.assertIn("} else if (!opening && !viewerError) {", self.ui)
        self.assertIn("Nie udało się otworzyć pulpitu:", self.ui)

    def test_viewer_failure_survives_next_poll_and_end_cleans_pending_tab(self):
        self.assertIn("viewerError = true;", self.ui)
        self.assertIn("!opening && !viewerError", self.ui)
        self.assertIn("autoOpen=false; viewerError=false;", self.ui)
        self.assertIn("if(viewerTab && !viewerTab.closed) viewerTab.close(); viewerTab=null;", self.ui)

    def test_session_polling_is_serialized(self):
        self.assertIn("refreshPending = false;", self.ui)
        self.assertIn("if (!sid || refreshPending) return;", self.ui)
        self.assertIn("refreshPending = true;", self.ui)
        self.assertIn("} finally {\n          refreshPending = false;", self.ui)

    def test_recover_does_not_accumulate_polling_intervals(self):
        self.assertIn("if (timer) { clearInterval(timer); timer = null; }", self.ui)
        self.assertIn("timer = setInterval(refresh, 3000);", self.ui)
        self.assertIn("timer=null; sid=null; autoOpen=false; viewerError=false;", self.ui)

    def test_pending_requests_ignore_stale_session_results(self):
        self.assertIn("const checkedSession = sid;", self.ui)
        self.assertIn("if (sid !== checkedSession) return;", self.ui)
        self.assertIn("const connectingSession = sid;", self.ui)
        self.assertIn("if (sid !== connectingSession)", self.ui)
        self.assertIn("if (tab) tab.close();", self.ui)

    def test_popup_block_does_not_create_orphan_mesh_share(self):
        self.assertIn("if (!tab) {", self.ui)
        self.assertIn("opening = false;", self.ui)
        self.assertIn("viewerError = true;", self.ui)
        self.assertLess(self.ui.index("if (!tab) {"),
                        self.ui.index("const reply = await api('sessions/' + connectingSession + '/connect','POST')"))

    def test_service_connect_disables_button_before_network_request(self):
        handler = self.ui.split("start.onclick = async () => {", 1)[1].split("consent.onclick = async () => {", 1)[0]
        self.assertIn("if (!standingEligible)", handler)
        self.assertNotIn("window.confirm(", handler)
        self.assertLess(handler.index("start.disabled = true;", handler.index("prepareViewer();")),
                        handler.index("await api('request/' + installation, 'POST')"))

    def test_button_colors_and_disabled_gates(self):
        for needle in ("#ws-start{background:#1764b0}", "#ws-connect{background:#16834a}", "#ws-end{background:#be3030}", ".ws-controls button:disabled", 'id="ws-connect" disabled', 'id="ws-end" disabled'):
            with self.subTest(needle=needle): self.assertIn(needle, self.ui)

    def test_no_green_desktop_before_binding(self):
        self.assertIn('result["meshLinked"] = workshop.session_node_ready(grant, row)', self.status)
        self.assertIn('const ready = info.meshLinked === true;', self.ui)
        self.assertIn('connect.disabled = !ready;', self.ui)
        self.assertIn('Oczekiwanie na powiązanie MeshAgenta', self.ui)

    def test_refresh_recovers_server_session_without_duplicate_start(self):
        self.assertIn("async function recover()", self.ui)
        self.assertIn("await api('active/' + installation)", self.ui)
        self.assertIn("sid = data.session.sessionId;", self.ui)
        self.assertIn("start.disabled = true;", self.ui)
        self.assertIn("recover();", self.ui)
        self.assertIn("FROM guard.workshop_remote_sessions", self.active)
        self.assertIn("status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')", self.active)
        self.assertIn('result["meshLinked"]', self.active)

    def test_reset_on_end(self):
        self.assertIn("connect.disabled=true; end.disabled=true; start.disabled=true; consent.disabled=true;", self.ui)
        self.assertIn("await refreshApproval();", self.ui)
        self.assertIn("sid=null;", self.ui)
        self.assertIn("end.disabled=false;status.textContent=e.message;", self.ui)


if __name__ == "__main__":
    unittest.main()
