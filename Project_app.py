import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from pii_detector import PIIDetector
import io

# ------------------------------------------------------------
# Page configuration
# ------------------------------------------------------------
st.set_page_config(
    page_title="Dataset Privacy Auditor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------
# Material-inspired soft UI (KFUPM-leaning green)
# ------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    :root {
        --primary: #0F7C4A;          /* KFUPM-ish green */
        --primary-strong: #065F38;
        --primary-soft: #E6F3EC;
        --bg: light-dark(#F4F5FB, #0F172A);
        --surface: light-dark(#FFFFFF, #1E293B);
        --surface-alt: light-dark(#F9FAFB, #334155);
        --text-main: light-dark(#0F172A, #F1F5F9);
        --text-muted: light-dark(#6B7280, #CBD5E1);
        --border-subtle: light-dark(#E5E7EB, #475569);
        --chip-bg: #EEF2FF;
        color-scheme: light dark;
    }

    .stApp {
        background-color: var(--bg);
        font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }

    .block-container {
        padding-top: 2.5rem;
        padding-bottom: 2.5rem;
        max-width: 1180px;
    }

    /* Header */
    .app-header {
        margin-bottom: 1.8rem;
    }

    .app-title {
        font-size: 2.1rem;
        font-weight: 600;
        letter-spacing: -0.03em;
        color: var(--text-main);
        margin-bottom: 0.25rem;
    }

    .app-subtitle {
        font-size: 0.98rem;
        color: var(--text-muted);
        max-width: 650px;
        line-height: 1.55;
    }

    .app-accent {
        margin-top: 1rem;
        width: 64px;
        height: 3px;
        border-radius: 999px;
        background: linear-gradient(90deg, var(--primary), var(--primary-strong));
    }

    /* Cards */
    .surface-card {
        background-color: var(--surface);
        border-radius: 18px;
        border: 1px solid var(--border-subtle);
        padding: 1.4rem 1.5rem;
        box-shadow: 0 18px 40px rgba(15, 23, 42, 0.04);
    }

    .surface-subtle {
        background-color: var(--surface-alt);
        border-radius: 18px;
        border: 1px solid var(--border-subtle);
        padding: 1.2rem 1.3rem;
    }

    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-main);
        margin-bottom: 0.35rem;
    }

    .section-hint {
        font-size: 0.9rem;
        color: var(--text-muted);
        margin-bottom: 0.9rem;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: var(--surface);
        border-right: 1px solid var(--border-subtle);
    }

    [data-testid="stSidebar"] h1 {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 0.4rem;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        border-radius: 16px;
        border: 1.5px dashed var(--border-subtle);
        background-color: var(--surface-alt);
        padding: 1.4rem;
    }

    [data-testid="stFileUploader"]:hover {
        border-color: var(--primary);
    }

    /* Primary buttons */
    .stButton > button {
        border-radius: 999px;
        background: var(--primary) !important;
        color: white !important;
        border: 1px solid var(--primary-strong) !important;
        font-size: 0.92rem;
        font-weight: 500;
        padding: 0.4rem 1.4rem;
        letter-spacing: 0.01em;
        box-shadow: 0 12px 30px rgba(5, 122, 85, 0.25);
        transition: all 0.16s ease;
    }

    .stButton > button:hover {
        background: var(--primary-strong) !important;
        transform: translateY(-1px);
        box-shadow: 0 16px 38px rgba(5, 122, 85, 0.3);
    }

    /* Metrics */
    [data-testid="metric-container"] {
        border-radius: 16px;
        padding: 0.6rem 0.8rem;
        background-color: var(--surface);
        border: 1px solid var(--border-subtle);
    }

    /* Dataframe */
    .stDataFrame {
        border-radius: 16px;
        border: 1px solid var(--border-subtle);
    }

    /* Download buttons */
    .stDownloadButton > button {
        border-radius: 999px !important;
        background-color: var(--surface) !important;
        color: var(--text-main) !important;
        border: 1px solid var(--border-subtle) !important;
        font-size: 0.9rem !important;
        padding: 0.4rem 1.3rem !important;
        transition: all 0.15s ease;
    }

    .stDownloadButton > button:hover {
        border-color: var(--primary) !important;
        color: var(--primary) !important;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
    }

    p {
        line-height: 1.6;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------
# Main Application
# ------------------------------------------------------------
def main():

    # Header
    st.markdown(
        """
        <div class="app-header">
            <div class="app-title">Dataset Privacy Auditor</div>
            <div class="app-subtitle">
                Upload a tabular dataset, scan it for potential personal data, and obtain a
                clear, structured summary of privacy risk you can present or discuss.
            </div>
            <div class="app-accent"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar
    with st.sidebar:
        st.markdown("#### About this tool")
        st.write(
            "The auditor runs pattern-based checks to highlight columns that may "
            "contain personally identifiable information (PII) in CSV or Excel datasets."
        )

        st.markdown("#### What the output provides")
        st.write(
            "- A list of columns that look sensitive\n"
            "- A risk category for each flagged column\n"
            "- Simple visual summaries\n"
            "- Downloadable report files"
        )

        st.markdown("#### Course context")
        st.write("KFUPM · COE 426 – Data Privacy · Term 251")

        st.markdown("#### Project team")
        st.write(
            "Danah Aljameel | \n"
            "Lamyaa Alyousef | \n"
            "Malath Alhashem | \n"
             "Rimas Alghamdi | \n"
            "Sara Alshayeb"
            
           
            
        )

    # Layout: left (workflow) / right (explanation)
    col_main, col_side = st.columns([2.2, 1.0], gap="large")

    # --------------------------------------------------------
    # Main workflow (upload → analyse → results)
    # --------------------------------------------------------
    with col_main:
        st.markdown(
            '<div class="section-title">Upload a dataset</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="section-hint">'
            'Supported formats: CSV and Excel. Each column will be scanned independently '
            'for possible PII patterns such as emails, phone numbers, or IDs.'
            "</div>",
            unsafe_allow_html=True,
        )

        uploaded_file = st.file_uploader(
            "Upload file",
            type=["csv", "xlsx", "xls"],
            label_visibility="collapsed",
        )

        if uploaded_file is not None:
            try:
                # Load dataset
                if uploaded_file.name.endswith(".csv"):
                    df = pd.read_csv(uploaded_file)
                else:
                    df = pd.read_excel(uploaded_file)

                st.success(
                    f"File loaded successfully: {len(df)} rows × {len(df.columns)} columns."
                )

                # Preview
                with st.expander("Preview sample (first 10 rows)"):
                    st.dataframe(df.head(10), use_container_width=True)
                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.metric("Rows", len(df))
                    with m2:
                        st.metric("Columns", len(df.columns))
                    with m3:
                        mem_kb = df.memory_usage(deep=True).sum() / 1024
                        st.metric("Approx. memory", f"{mem_kb:.1f} KB")

                # Run analysis
                run = st.button("Run privacy analysis")

                if run:
                    with st.spinner("Scanning columns for possible personal data..."):
                        detector = PIIDetector()
                        results_df = detector.analyze_dataset(df)

                    if len(results_df) == 0:
                        st.info(
                            "No columns were flagged by the detector. "
                            "This is encouraging, but it does not fully guarantee the absence of PII."
                        )
                        st.session_state["results_df"] = None
                        st.session_state["source_df"] = df
                    else:
                        st.success(
                            f"Analysis complete. {len(results_df)} column(s) were flagged as potentially containing PII."
                        )
                        st.session_state["results_df"] = results_df
                        st.session_state["source_df"] = df

                # Results section
                if (
                    "results_df" in st.session_state
                    and st.session_state["results_df"] is not None
                ):
                    results_df = st.session_state["results_df"]

                    st.markdown("---")
                    st.markdown(
                        '<div class="section-title">Summary of findings</div>',
                        unsafe_allow_html=True,
                    )
                    st.markdown(
                        '<div class="section-hint">'
                        "Columns are grouped into broad risk categories to support decisions "
                        "about masking, anonymisation, or removal."
                        "</div>",
                        unsafe_allow_html=True,
                    )

                    c1, c2, c3, c4 = st.columns(4)
                    high = len(results_df[results_df["Risk Category"] == "High"])
                    med = len(results_df[results_df["Risk Category"] == "Medium"])
                    low = len(results_df[results_df["Risk Category"] == "Low"])
                    avg_risk = (
                        results_df["Risk Score"]
                        .str.replace("%", "")
                        .astype(float)
                        .mean()
                    )

                    c1.metric("High risk", high)
                    c2.metric("Medium risk", med)
                    c3.metric("Low risk", low)
                    c4.metric("Average risk", f"{avg_risk:.1f}%")

                    # Visual overview
                    st.markdown(
                        '<div class="section-title" style="margin-top:1.2rem;">Visual overview</div>',
                        unsafe_allow_html=True,
                    )
                    v1, v2 = st.columns(2)

                    with v1:
                        risk_counts = results_df["Risk Category"].value_counts()
                        risk_colors = {
                            "High": "#DC2626",
                            "Medium": "#D97706",
                            "Low": "#16A34A",
                        }
                        fig_pie = go.Figure(
                            data=[
                                go.Pie(
                                    labels=list(risk_counts.index),
                                    values=list(risk_counts.values),
                                    hole=0.45,
                                    marker=dict(
                                        colors=[
                                            risk_colors.get(cat, "#9CA3AF")
                                            for cat in risk_counts.index
                                        ]
                                    ),
                                )
                            ]
                        )
                        fig_pie.update_layout(
                            height=320,
                            margin=dict(l=10, r=10, t=40, b=10),
                            title_text="Columns by risk category",
                        )
                        st.plotly_chart(fig_pie, use_container_width=True)

                    with v2:
                        pii_counts = results_df["PII Type"].value_counts()
                        fig_bar = go.Figure(
                            data=[
                                go.Bar(
                                    x=list(pii_counts.values),
                                    y=list(pii_counts.index),
                                    orientation="h",
                                )
                            ]
                        )
                        fig_bar.update_layout(
                            height=320,
                            margin=dict(l=80, r=10, t=40, b=40),
                            title_text="Detected PII types (per column)",
                            xaxis_title="Number of columns",
                            yaxis_title="PII type",
                        )
                        st.plotly_chart(fig_bar, use_container_width=True)

                    # Column-level details
                    st.markdown(
                        '<div class="section-title">Column-level details</div>',
                        unsafe_allow_html=True,
                    )
                    st.markdown(
                        '<div class="section-hint">'
                        "Each row describes one flagged column, including its PII type, "
                        "risk assessment, and a suggested action."
                        "</div>",
                        unsafe_allow_html=True,
                    )
                    st.dataframe(results_df, use_container_width=True, height=420)

                    # Export
                    st.markdown(
                        '<div class="section-title">Export options</div>',
                        unsafe_allow_html=True,
                    )
                    ex1, ex2 = st.columns(2)

                    with ex1:
                        csv_data = results_df.to_csv(index=False)
                        st.download_button(
                            label="Download report as CSV",
                            data=csv_data,
                            file_name="privacy_audit_report.csv",
                            mime="text/csv",
                        )

                    with ex2:
                        buffer = io.BytesIO()
                        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                            results_df.to_excel(
                                writer, index=False, sheet_name="PII analysis"
                            )
                            st.session_state["source_df"].head(100).to_excel(
                                writer, index=False, sheet_name="Dataset sample"
                            )
                        st.download_button(
                            label="Download report as Excel",
                            data=buffer.getvalue(),
                            file_name="privacy_audit_report.xlsx",
                            mime=(
                                "application/vnd.openxmlformats-officedocument."
                                "spreadsheetml.sheet"
                            ),
                        )

            except Exception as e:
                st.error(f"Error reading file: {e}")

        else:
            st.info(
                "Start by uploading a dataset. If you want, you can first remove obvious identifiers "
                "to see how that changes the risk assessment."
            )

    # --------------------------------------------------------
    # Side panel: interpretation / guidance
    # --------------------------------------------------------
    with col_side:
        st.markdown(
            '<div class="surface-subtle">'
            '<div class="section-title">How to read the results</div>'
            '<div class="section-hint">'
            "The analysis is pattern-based and should be treated as a starting point, not a final decision. "
            "Context and course requirements still matter."
            "</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            - **High risk**: columns that contain direct identifiers or detailed contact information.
            - **Medium risk**: fields that may become identifying when combined with other columns.
            - **Low risk**: fields where patterns are weaker but still worth a quick review.
            
            
            """,
            unsafe_allow_html=False,
        )
        st.markdown("</div>", unsafe_allow_html=True)


# ------------------------------------------------------------
# Run
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
