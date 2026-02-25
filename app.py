"""
SIEM Dashboard - Main Application
"""
import os
import yaml
from datetime import datetime, timedelta
from flask import Flask, render_template
import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import plotly.express as px
from sqlalchemy import func
import pandas as pd

from models import db, LogEntry, ThreatAlert, ComplianceReport, SystemMetrics
from log_parser import LogParser
from threat_detector import ThreatDetector
from compliance import ComplianceChecker


# Load configuration
with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Initialize Flask app
server = Flask(__name__)
server.config['SQLALCHEMY_DATABASE_URI'] = config['database']['uri']
server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
server.config['SECRET_KEY'] = config['app'].get('secret_key', 'dev-secret-key')

# Initialize database
db.init_app(server)

# Initialize Dash app
app = dash.Dash(
    __name__,
    server=server,
    external_stylesheets=[dbc.themes.DARKLY],
    suppress_callback_exceptions=True
)

# Initialize SIEM components
log_parser = LogParser()
threat_detector = ThreatDetector(config)
compliance_checker = ComplianceChecker(config)


# Dashboard Layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("🛡️ SIEM Dashboard", className="text-center mb-4 mt-4"),
            html.Hr()
        ])
    ]),
    
    # Summary Cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Total Logs", className="card-title"),
                    html.H2(id="total-logs", className="text-info"),
                    html.P("Last 24 hours", className="text-muted")
                ])
            ], className="mb-4")
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Active Threats", className="card-title"),
                    html.H2(id="active-threats", className="text-danger"),
                    html.P("Open alerts", className="text-muted")
                ])
            ], className="mb-4")
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Critical Alerts", className="card-title"),
                    html.H2(id="critical-alerts", className="text-warning"),
                    html.P("Last 24 hours", className="text-muted")
                ])
            ], className="mb-4")
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Compliance Score", className="card-title"),
                    html.H2(id="compliance-score", className="text-success"),
                    html.P("Average across frameworks", className="text-muted")
                ])
            ], className="mb-4")
        ], width=3),
    ]),
    
    # Tabs for different views
    dbc.Tabs([
        # Overview Tab
        dbc.Tab(label="Overview", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Log Activity Timeline"),
                        dbc.CardBody([
                            dcc.Graph(id="log-timeline")
                        ])
                    ], className="mt-3")
                ], width=8),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Severity Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id="severity-pie")
                        ])
                    ], className="mt-3")
                ], width=4),
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Top Source IPs"),
                        dbc.CardBody([
                            dcc.Graph(id="top-ips")
                        ])
                    ], className="mt-3")
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Log Types Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id="log-types")
                        ])
                    ], className="mt-3")
                ], width=6),
            ])
        ]),
        
        # Threat Detection Tab
        dbc.Tab(label="Threat Detection", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Threat Alert Timeline"),
                        dbc.CardBody([
                            dcc.Graph(id="threat-timeline")
                        ])
                    ], className="mt-3")
                ], width=12),
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Types"),
                        dbc.CardBody([
                            dcc.Graph(id="alert-types")
                        ])
                    ], className="mt-3")
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Severity Breakdown"),
                        dbc.CardBody([
                            dcc.Graph(id="threat-severity")
                        ])
                    ], className="mt-3")
                ], width=6),
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recent Alerts"),
                        dbc.CardBody([
                            html.Div(id="recent-alerts")
                        ])
                    ], className="mt-3")
                ], width=12),
            ])
        ]),
        
        # Compliance Tab
        dbc.Tab(label="Compliance Reports", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Compliance Framework Scores"),
                        dbc.CardBody([
                            dcc.Graph(id="compliance-scores")
                        ])
                    ], className="mt-3")
                ], width=12),
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Framework Details"),
                        dbc.CardBody([
                            dbc.Select(
                                id="framework-selector",
                                options=[
                                    {"label": "PCI-DSS", "value": "PCI-DSS"},
                                    {"label": "HIPAA", "value": "HIPAA"},
                                    {"label": "GDPR", "value": "GDPR"},
                                    {"label": "SOC2", "value": "SOC2"},
                                ],
                                value="PCI-DSS",
                                className="mb-3"
                            ),
                            html.Div(id="compliance-details")
                        ])
                    ], className="mt-3")
                ], width=12),
            ])
        ]),
        
        # Analytics Tab
        dbc.Tab(label="Analytics", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Geographic Distribution (Top Source IPs)"),
                        dbc.CardBody([
                            dcc.Graph(id="geo-map")
                        ])
                    ], className="mt-3")
                ], width=12),
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Hourly Traffic Pattern"),
                        dbc.CardBody([
                            dcc.Graph(id="hourly-pattern")
                        ])
                    ], className="mt-3")
                ], width=12),
            ])
        ])
    ], className="mt-3"),
    
    # Auto-refresh interval
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # 30 seconds
        n_intervals=0
    )
], fluid=True)


# Callbacks
@app.callback(
    [Output("total-logs", "children"),
     Output("active-threats", "children"),
     Output("critical-alerts", "children"),
     Output("compliance-score", "children")],
    [Input("interval-component", "n_intervals")]
)
def update_summary_cards(n):
    """Update summary statistics"""
    with server.app_context():
        # Total logs in last 24 hours
        day_ago = datetime.now() - timedelta(days=1)
        total_logs = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= day_ago
        ).count()
        
        # Active threats
        active_threats = db.session.query(ThreatAlert).filter(
            ThreatAlert.status == 'open'
        ).count()
        
        # Critical alerts in last 24 hours
        critical_alerts = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= day_ago,
            ThreatAlert.severity == 'critical'
        ).count()
        
        # Average compliance score
        avg_score = db.session.query(func.avg(ComplianceReport.compliance_score)).filter(
            ComplianceReport.report_date >= day_ago
        ).scalar()
        
        compliance_score = f"{avg_score:.1f}%" if avg_score else "N/A"
        
        return f"{total_logs:,}", f"{active_threats}", f"{critical_alerts}", compliance_score


@app.callback(
    Output("log-timeline", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_log_timeline(n):
    """Update log activity timeline"""
    with server.app_context():
        day_ago = datetime.now() - timedelta(days=1)
        
        logs = db.session.query(
            func.date_trunc('hour', LogEntry.timestamp).label('hour'),
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= day_ago
        ).group_by('hour').order_by('hour').all()
        
        df = pd.DataFrame(logs, columns=['hour', 'count'])
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['hour'],
            y=df['count'],
            mode='lines+markers',
            name='Log Count',
            line=dict(color='#00d4ff', width=2)
        ))
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Time',
            yaxis_title='Log Count',
            hovermode='x unified',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("severity-pie", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_severity_pie(n):
    """Update severity distribution pie chart"""
    with server.app_context():
        day_ago = datetime.now() - timedelta(days=1)
        
        severity_counts = db.session.query(
            LogEntry.severity,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= day_ago
        ).group_by(LogEntry.severity).all()
        
        df = pd.DataFrame(severity_counts, columns=['severity', 'count'])
        
        colors = {
            'critical': '#ff0000',
            'error': '#ff6b6b',
            'warning': '#ffa500',
            'info': '#00d4ff',
            'debug': '#888888'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=df['severity'],
            values=df['count'],
            marker=dict(colors=[colors.get(s, '#888888') for s in df['severity']])
        )])
        
        fig.update_layout(
            template='plotly_dark',
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        return fig


@app.callback(
    Output("top-ips", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_top_ips(n):
    """Update top source IPs"""
    with server.app_context():
        day_ago = datetime.now() - timedelta(days=1)
        
        top_ips = db.session.query(
            LogEntry.ip_address,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= day_ago,
            LogEntry.ip_address.isnot(None)
        ).group_by(LogEntry.ip_address).order_by(func.count(LogEntry.id).desc()).limit(10).all()
        
        df = pd.DataFrame(top_ips, columns=['ip_address', 'count'])
        
        fig = go.Figure([go.Bar(
            x=df['count'],
            y=df['ip_address'],
            orientation='h',
            marker=dict(color='#00d4ff')
        )])
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Request Count',
            yaxis_title='IP Address',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("log-types", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_log_types(n):
    """Update log types distribution"""
    with server.app_context():
        day_ago = datetime.now() - timedelta(days=1)
        
        log_types = db.session.query(
            LogEntry.log_type,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= day_ago
        ).group_by(LogEntry.log_type).all()
        
        df = pd.DataFrame(log_types, columns=['log_type', 'count'])
        
        fig = go.Figure([go.Bar(
            x=df['log_type'],
            y=df['count'],
            marker=dict(color='#00d4ff')
        )])
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Log Type',
            yaxis_title='Count',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("threat-timeline", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_threat_timeline(n):
    """Update threat alert timeline"""
    with server.app_context():
        week_ago = datetime.now() - timedelta(days=7)
        
        threats = db.session.query(
            func.date_trunc('day', ThreatAlert.timestamp).label('day'),
            ThreatAlert.severity,
            func.count(ThreatAlert.id).label('count')
        ).filter(
            ThreatAlert.timestamp >= week_ago
        ).group_by('day', ThreatAlert.severity).order_by('day').all()
        
        df = pd.DataFrame(threats, columns=['day', 'severity', 'count'])
        
        fig = go.Figure()
        
        for severity in df['severity'].unique():
            severity_data = df[df['severity'] == severity]
            fig.add_trace(go.Scatter(
                x=severity_data['day'],
                y=severity_data['count'],
                mode='lines+markers',
                name=severity,
                stackgroup='one'
            ))
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Date',
            yaxis_title='Alert Count',
            hovermode='x unified',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("alert-types", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_alert_types(n):
    """Update alert types distribution"""
    with server.app_context():
        week_ago = datetime.now() - timedelta(days=7)
        
        alert_types = db.session.query(
            ThreatAlert.alert_type,
            func.count(ThreatAlert.id).label('count')
        ).filter(
            ThreatAlert.timestamp >= week_ago
        ).group_by(ThreatAlert.alert_type).all()
        
        df = pd.DataFrame(alert_types, columns=['alert_type', 'count'])
        
        fig = go.Figure([go.Bar(
            x=df['alert_type'],
            y=df['count'],
            marker=dict(color='#ff6b6b')
        )])
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Alert Type',
            yaxis_title='Count',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("threat-severity", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_threat_severity(n):
    """Update threat severity breakdown"""
    with server.app_context():
        week_ago = datetime.now() - timedelta(days=7)
        
        severity_counts = db.session.query(
            ThreatAlert.severity,
            func.count(ThreatAlert.id).label('count')
        ).filter(
            ThreatAlert.timestamp >= week_ago
        ).group_by(ThreatAlert.severity).all()
        
        df = pd.DataFrame(severity_counts, columns=['severity', 'count'])
        
        colors = {
            'critical': '#ff0000',
            'high': '#ff6b6b',
            'medium': '#ffa500',
            'low': '#ffff00'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=df['severity'],
            values=df['count'],
            marker=dict(colors=[colors.get(s, '#888888') for s in df['severity']])
        )])
        
        fig.update_layout(
            template='plotly_dark',
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        return fig


@app.callback(
    Output("recent-alerts", "children"),
    [Input("interval-component", "n_intervals")]
)
def update_recent_alerts(n):
    """Update recent alerts table"""
    with server.app_context():
        recent_alerts = db.session.query(ThreatAlert).order_by(
            ThreatAlert.timestamp.desc()
        ).limit(10).all()
        
        if not recent_alerts:
            return html.P("No recent alerts", className="text-muted")
        
        rows = []
        for alert in recent_alerts:
            badge_color = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'secondary'
            }.get(alert.severity, 'secondary')
            
            rows.append(html.Tr([
                html.Td(alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A'),
                html.Td(alert.alert_type),
                html.Td(dbc.Badge(alert.severity, color=badge_color)),
                html.Td(alert.source_ip or 'N/A'),
                html.Td(alert.description[:50] + '...' if len(alert.description) > 50 else alert.description),
                html.Td(dbc.Badge(alert.status, color='success' if alert.status == 'resolved' else 'warning'))
            ]))
        
        table = dbc.Table([
            html.Thead(html.Tr([
                html.Th("Timestamp"),
                html.Th("Type"),
                html.Th("Severity"),
                html.Th("Source IP"),
                html.Th("Description"),
                html.Th("Status")
            ])),
            html.Tbody(rows)
        ], bordered=True, hover=True, responsive=True, striped=True)
        
        return table


@app.callback(
    Output("compliance-scores", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_compliance_scores(n):
    """Update compliance scores chart"""
    with server.app_context():
        # Get latest report for each framework
        frameworks = ['PCI-DSS', 'HIPAA', 'GDPR', 'SOC2']
        scores = []
        
        for framework in frameworks:
            report = db.session.query(ComplianceReport).filter(
                ComplianceReport.framework == framework
            ).order_by(ComplianceReport.report_date.desc()).first()
            
            if report:
                scores.append({
                    'framework': framework,
                    'score': report.compliance_score,
                    'passed': report.passed_checks,
                    'failed': report.failed_checks
                })
            else:
                scores.append({
                    'framework': framework,
                    'score': 0,
                    'passed': 0,
                    'failed': 0
                })
        
        df = pd.DataFrame(scores)
        
        fig = go.Figure([go.Bar(
            x=df['framework'],
            y=df['score'],
            marker=dict(color='#00d4ff'),
            text=df['score'].round(1),
            textposition='auto'
        )])
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Framework',
            yaxis_title='Compliance Score (%)',
            yaxis_range=[0, 100],
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


@app.callback(
    Output("compliance-details", "children"),
    [Input("framework-selector", "value"),
     Input("interval-component", "n_intervals")]
)
def update_compliance_details(framework, n):
    """Update compliance framework details"""
    with server.app_context():
        report = db.session.query(ComplianceReport).filter(
            ComplianceReport.framework == framework
        ).order_by(ComplianceReport.report_date.desc()).first()
        
        if not report:
            return html.P(f"No compliance report available for {framework}", className="text-muted")
        
        details = report.details.get('checks', [])
        
        rows = []
        for check in details:
            badge_color = {
                'passed': 'success',
                'failed': 'danger',
                'warning': 'warning'
            }.get(check['status'], 'secondary')
            
            rows.append(html.Tr([
                html.Td(check['requirement']),
                html.Td(check.get('description', 'N/A')),
                html.Td(dbc.Badge(check['status'], color=badge_color)),
                html.Td(check.get('details', 'N/A'))
            ]))
        
        table = dbc.Table([
            html.Thead(html.Tr([
                html.Th("Requirement"),
                html.Th("Description"),
                html.Th("Status"),
                html.Th("Details")
            ])),
            html.Tbody(rows)
        ], bordered=True, hover=True, responsive=True, striped=True)
        
        summary = html.Div([
            html.H5(f"{framework} Compliance Report"),
            html.P([
                f"Score: {report.compliance_score:.1f}% | ",
                f"Passed: {report.passed_checks} | ",
                f"Failed: {report.failed_checks} | ",
                f"Total: {report.total_checks}"
            ]),
            html.Hr(),
            table
        ])
        
        if report.recommendations:
            summary.children.append(html.Div([
                html.H6("Recommendations:", className="mt-3"),
                html.Ul([html.Li(rec) for rec in report.recommendations])
            ]))
        
        return summary


@app.callback(
    Output("geo-map", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_geo_map(n):
    """Update geographic distribution (mock data for demonstration)"""
    with server.app_context():
        day_ago = datetime.now() - timedelta(days=1)
        
        top_ips = db.session.query(
            LogEntry.ip_address,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= day_ago,
            LogEntry.ip_address.isnot(None)
        ).group_by(LogEntry.ip_address).order_by(func.count(LogEntry.id).desc()).limit(20).all()
        
        # Mock geographic data (in production, use IP geolocation service)
        import random
        geo_data = []
        for ip, count in top_ips:
            geo_data.append({
                'ip': ip,
                'count': count,
                'lat': random.uniform(-90, 90),
                'lon': random.uniform(-180, 180)
            })
        
        df = pd.DataFrame(geo_data)
        
        if df.empty:
            fig = go.Figure()
        else:
            fig = go.Figure(data=go.Scattergeo(
                lon=df['lon'],
                lat=df['lat'],
                text=df['ip'],
                mode='markers',
                marker=dict(
                    size=df['count'] / df['count'].max() * 20 + 5,
                    color=df['count'],
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Requests")
                )
            ))
        
        fig.update_layout(
            template='plotly_dark',
            geo=dict(
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(50, 50, 50)',
                coastlinecolor='rgb(100, 100, 100)'
            ),
            margin=dict(l=0, r=0, t=40, b=0)
        )
        
        return fig


@app.callback(
    Output("hourly-pattern", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_hourly_pattern(n):
    """Update hourly traffic pattern"""
    with server.app_context():
        week_ago = datetime.now() - timedelta(days=7)
        
        hourly_data = db.session.query(
            func.extract('hour', LogEntry.timestamp).label('hour'),
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= week_ago
        ).group_by('hour').order_by('hour').all()
        
        df = pd.DataFrame(hourly_data, columns=['hour', 'count'])
        
        # Ensure all hours are present
        all_hours = pd.DataFrame({'hour': range(24)})
        df = all_hours.merge(df, on='hour', how='left').fillna(0)
        
        fig = go.Figure([go.Bar(
            x=df['hour'],
            y=df['count'],
            marker=dict(color='#00d4ff')
        )])
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Hour of Day',
            yaxis_title='Average Request Count',
            xaxis=dict(tickmode='linear', tick0=0, dtick=1),
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig


if __name__ == '__main__':
    with server.app_context():
        db.create_all()
    
    app.run_server(
        host=config['app']['host'],
        port=config['app']['port'],
        debug=config['app']['debug']
    )
