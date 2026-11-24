
import streamlit as st

from src.incident_manager import (
    init_db,
    list_incidents,
    get_incident,
    list_audit_events,
    update_incident_status,
)


def render_dashboard():
    st.title("🛡️ PhishGuard SOC")
    st.caption("Security Operations Center — Incident Management")

    init_db()

    incidents = list_incidents(limit=1000)

    total = len(incidents)
    critical = sum(i["risk_level"] == "CRITICAL" for i in incidents)
    high = sum(i["risk_level"] == "HIGH" for i in incidents)
    investigating = sum(
        i["status"] == "INVESTIGATING" for i in incidents
    )
    unresolved = sum(
        i["status"] in {"NEW", "INVESTIGATING"}
        for i in incidents
    )

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Incidents", total)
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("Unresolved", unresolved)

    st.divider()

    st.subheader("Incident History")

    if not incidents:
        st.info("No incidents recorded yet.")
        return

    status_filter = st.selectbox(
        "Filter by status",
        ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
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
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    st.subheader("Incident Investigation")

    incident_options = {
        f'{item["id"][:8]} — {item["subject"] or "No subject"}':
            item["id"]
        for item in filtered
    }

    if not incident_options:
        st.info("No incidents match this filter.")
        return

    selected_label = st.selectbox(
        "Select an incident",
        list(incident_options.keys()),
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

    analysis = incident["analysis"]

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
                    st.markdown(
                        f"[MITRE reference]({technique['url']})"
                    )
        else:
            st.info("No MITRE techniques recorded.")

    with st.expander("Attachment Analysis"):
        attachments = analysis.get("attachments", [])

        if attachments:
            for attachment in attachments:
                st.write(
                    f"Filename: {attachment.get('filename', 'unknown')}"
                )
                st.write(
                    f"SHA-256: {attachment.get('sha256', '')}"
                )
                st.write(
                    f"Size: {attachment.get('size', 0)} bytes"
                )
        else:
            st.info("No attachment information.")

    with st.expander("Audit Trail", expanded=False):
        events = list_audit_events(incident_id, limit=100)

        if events:
            st.caption(f"{len(events)} audit event(s) — newest first")

            for event in events:
                st.markdown(
                    f"**{event['action']}** — "
                    f"Actor: `{event['actor']}`"
                )

                old_status = event.get("old_status") or "—"
                new_status = event.get("new_status") or "—"

                if event["action"] == "STATUS_CHANGED":
                    st.write(
                        f"Status transition: **{old_status}** → "
                        f"**{new_status}**"
                    )

                st.caption(f"Date: {event['created_at']}")
                st.divider()
        else:
            st.info("No audit events recorded for this incident.")

    st.divider()
    st.subheader("Analyst Actions")

    status_options = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
    ]

    current_index = (
        status_options.index(incident["status"])
        if incident["status"] in status_options else 0
    )

    new_status = st.selectbox(
        "Update status",
        status_options,
        index=current_index,
    )

    analyst_note = st.text_area(
        "Analyst notes",
        value=incident["analyst_note"],
        max_chars=5000,
    )

    if st.button("Save Investigation", type="primary"):
        success = update_incident_status(
            incident_id,
            new_status,
            analyst_note,
        )

        if success:
            st.success("Incident updated successfully.")
            st.rerun()
        else:
            st.error("Could not update incident.")

