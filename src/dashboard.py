import streamlit as st

from src.incident_manager import (
    init_db,
    list_incidents,
    get_incident,
    update_incident_status,
    list_audit_events,
)
from src.report_generator import (
    generate_pdf_report,
    generate_json_report,
    calculate_sha256,
)

STATUS_OPTIONS = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


def render_dashboard():
    # Appelé depuis app.py (onglet « Incidents ») : pas de st.title ici.
    st.subheader("Gestion des incidents")
    st.caption("Security Operations Center — Incident Management")

    init_db()

    incidents = list_incidents(limit=1000)

    total = len(incidents)
    critical = sum(i["risk_level"] == "CRITICAL" for i in incidents)
    high = sum(i["risk_level"] == "HIGH" for i in incidents)
    unresolved = sum(i["status"] in {"NEW", "INVESTIGATING"} for i in incidents)

    st.markdown("**Security Overview**")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Incidents", total)
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("Unresolved", unresolved)

    st.divider()
    st.markdown("**Incident History**")

    if not incidents:
        st.info("No incidents recorded yet.")
        return

    status_filter = st.selectbox(
        "Filter by status",
        ["ALL"] + STATUS_OPTIONS,
        key="dash_status_filter",
    )

    filtered = [
        item for item in incidents
        if status_filter == "ALL" or item["status"] == status_filter
    ]

    st.caption(f"Showing {len(filtered)} incidents")

    st.dataframe(
        [
            {
                "ID": item["id"][:8],
                "Subject": item["subject"],
                "Sender": item["sender"],
                "Risk": item["risk_level"],
                "Score": item["risk_score"],
                "Status": item["status"],
                "Created": item["created_at"],
            }
            for item in filtered
        ],
        hide_index=True,
    )

    st.divider()
    st.markdown("**Incident Investigation**")

    incident_options = {
        f'{item["id"][:8]} — {item["subject"] or "No subject"}': item["id"]
        for item in filtered
    }

    if not incident_options:
        st.info("No incidents match this filter.")
        return

    selected_label = st.selectbox(
        "Select an incident",
        list(incident_options.keys()),
        key="dash_selected_incident",
    )

    incident_id = incident_options[selected_label]
    incident = get_incident(incident_id)

    if incident is None:
        st.error("Incident not found.")
        return

    st.markdown(f"**Incident ID:** `{incident['id']}`")
    st.markdown(f"**Sender:** {incident['sender']}")
    st.markdown(f"**Subject:** {incident['subject']}")

    col1, col2 = st.columns(2)
    col1.metric("Risk Score", incident["risk_score"])
    col2.metric("Risk Level", incident["risk_level"])

    st.markdown(f"**Current Status:** {incident['status']}")

    analysis = incident.get("analysis") or {}

    with st.expander("Detection Findings", expanded=True):
        findings = analysis.get("findings", [])
        if findings:
            for finding in findings:
                st.markdown(
                    f"**{finding.get('type', 'Unknown')}** "
                    f"— {finding.get('severity', 'UNKNOWN')}"
                )
                st.write(finding.get("description", ""))
                if finding.get("evidence"):
                    st.caption(f"Evidence: {finding['evidence']}")
        else:
            st.info("No findings recorded.")

    with st.expander("MITRE ATT&CK"):
        techniques = analysis.get("mitre_techniques", [])
        if techniques:
            for technique in techniques:
                st.markdown(
                    f"**{technique.get('technique_id', '')}** — "
                    f"{technique.get('technique_name', '')}"
                )
                st.caption(technique.get("tactic", ""))
                if technique.get("url"):
                    st.markdown(f"[MITRE reference]({technique['url']})")
        else:
            st.info("No MITRE techniques recorded.")

    with st.expander("Attachment Analysis"):
        attachments = analysis.get("attachments", [])
        if attachments:
            for attachment in attachments:
                st.write(f"Filename: {attachment.get('filename', 'unknown')}")
                st.write(f"SHA-256: {attachment.get('sha256', '')}")
                st.write(f"Size: {attachment.get('size', 0)} bytes")
                st.divider()
        else:
            st.info("No attachment information.")

    st.divider()
    st.markdown("**Analyst Actions**")

    current_index = (
        STATUS_OPTIONS.index(incident["status"])
        if incident["status"] in STATUS_OPTIONS else 0
    )

    new_status = st.selectbox(
        "Update status",
        STATUS_OPTIONS,
        index=current_index,
        key=f"dash_status_{incident_id}",
    )

    analyst_note = st.text_area(
        "Analyst notes",
        value=incident.get("analyst_note") or "",
        max_chars=5000,
        key=f"dash_note_{incident_id}",
    )

    if st.button("Save Investigation", type="primary", key=f"dash_save_{incident_id}"):
        success = update_incident_status(incident_id, new_status, analyst_note)

        if success:
            st.success("Incident updated successfully.")
            st.rerun()
        else:
            st.error("Could not update incident.")

    with st.expander("Audit Trail", expanded=True):
        events = list_audit_events(incident_id)

        if events:
            for event in events:
                st.markdown(f"**{event['action']}** — {event['actor']}")

                if event["old_status"] or event["new_status"]:
                    st.caption(
                        f"{event['old_status'] or 'None'}"
                        f" → {event['new_status'] or 'None'}"
                    )

                st.caption(event["created_at"])
                st.divider()
        else:
            st.info("No audit events available.")

    st.divider()
    st.markdown("**Incident Reports**")

    try:
        pdf_content = generate_pdf_report(incident)
        json_content = generate_json_report(incident)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not generate reports: {exc}")
        return

    pdf_hash = calculate_sha256(pdf_content)
    st.caption(f"PDF SHA-256: `{pdf_hash}`")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Download PDF Report",
            data=pdf_content,
            file_name=f"incident_{incident_id[:8]}.pdf",
            mime="application/pdf",
            key=f"dash_pdf_{incident_id}",
        )

    with col2:
        st.download_button(
            "Download JSON Report",
            data=json_content,
            file_name=f"incident_{incident_id[:8]}.json",
            mime="application/json",
            key=f"dash_json_{incident_id}",
        )