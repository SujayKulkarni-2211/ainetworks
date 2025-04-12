import streamlit as st
import networkx as nx
import plotly.graph_objects as go
import numpy as np
import pandas as pd
import time
import json
import random
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime, timedelta
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_recall_curve
from sklearn.model_selection import train_test_split
import shap
import pickle
import os
import traceback
import logging
import uuid
import threading
import queue
import csv
import zipfile
import tempfile
from plotly.subplots import make_subplots
from io import BytesIO, StringIO
import plotly.express as px

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_simulator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("network_simulator")

# ------------------- PAGE SETUP -------------------
st.set_page_config(layout="wide", page_title="Network Security AI Simulator")

# Check if this is the first run or if reset was requested
if 'first_run' not in st.session_state:
    st.session_state.first_run = True

# ------------------- FUNCTION DEFINITIONS -------------------
def datetime_converter(obj):
    """Convert datetime objects to strings for JSON serialization"""
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def default_config():
    """Set up default network configuration with a single fixed topology."""
    try:
        # Medium sized network with fixed topology
        st.session_state.network_data["devices"] = {
            # Internal Segment - HR Department
            "HR-PC1": {"type": "pc", "ip": "192.168.1.10", "subnet": "hr", "status": "normal"},
            "HR-PC2": {"type": "pc", "ip": "192.168.1.11", "subnet": "hr", "status": "normal"},
            "HR-Server": {"type": "server", "ip": "192.168.1.50", "subnet": "hr", "status": "normal"},
            "HR-Switch": {"type": "switch", "ip": "192.168.1.2", "subnet": "hr", "status": "normal"},
            
            # Internal Segment - Finance Department
            "Finance-PC1": {"type": "pc", "ip": "192.168.2.10", "subnet": "finance", "status": "normal"},
            "Finance-PC2": {"type": "pc", "ip": "192.168.2.11", "subnet": "finance", "status": "normal"},
            "Finance-Server": {"type": "server", "ip": "192.168.2.50", "subnet": "finance", "status": "normal"},
            "Finance-Switch": {"type": "switch", "ip": "192.168.2.2", "subnet": "finance", "status": "normal"},
            
            # Core Network Infrastructure
            "Core-Switch": {"type": "switch", "ip": "10.10.10.2", "subnet": "core", "status": "normal"},
            "Core-Router": {"type": "router", "ip": "10.10.10.1", "subnet": "core", "status": "normal"},
            
            # DMZ
            "Web-Server": {"type": "server", "ip": "10.0.0.80", "subnet": "dmz", "status": "normal"},
            "Mail-Server": {"type": "server", "ip": "10.0.0.25", "subnet": "dmz", "status": "normal"},
            "DNS-Server": {"type": "server", "ip": "10.0.0.53", "subnet": "dmz", "status": "normal"},
            "DMZ-Switch": {"type": "switch", "ip": "10.0.0.2", "subnet": "dmz", "status": "normal"},
            
            # Security Infrastructure
            "IDS": {"type": "ids", "ip": "10.10.10.30", "subnet": "core", "status": "normal"},
            "Internal-Firewall": {"type": "firewall", "ip": "10.10.10.20", "subnet": "core", "status": "normal"},
            "External-Firewall": {"type": "firewall", "ip": "203.0.113.2", "subnet": "edge", "status": "normal"},
            
            # External 
            "Edge-Router": {"type": "router", "ip": "203.0.113.1", "subnet": "edge", "status": "normal"},
            "Internet": {"type": "cloud", "ip": "8.8.8.8", "subnet": "external", "status": "normal"}
        }
        
        st.session_state.network_data["connections"] = [
            # HR Network
            ("HR-PC1", "HR-Switch"), ("HR-PC2", "HR-Switch"),
            ("HR-Server", "HR-Switch"), ("HR-Switch", "Internal-Firewall"),
            
            # Finance Network
            ("Finance-PC1", "Finance-Switch"), ("Finance-PC2", "Finance-Switch"),
            ("Finance-Server", "Finance-Switch"), ("Finance-Switch", "Internal-Firewall"),
            
            # Core Network
            ("Internal-Firewall", "Core-Switch"), ("Core-Switch", "Core-Router"),
            ("Core-Switch", "IDS"), ("Core-Router", "External-Firewall"),
            
            # DMZ
            ("External-Firewall", "DMZ-Switch"), ("Web-Server", "DMZ-Switch"),
            ("Mail-Server", "DMZ-Switch"), ("DNS-Server", "DMZ-Switch"),
            
            # External
            ("External-Firewall", "Edge-Router"), ("Edge-Router", "Internet")
        ]
        
        st.session_state.network_data["subnets"] = {
            "hr": {"cidr": "192.168.1.0/24", "color": "#3498db", "description": "HR Department"},
            "finance": {"cidr": "192.168.2.0/24", "color": "#2ecc71", "description": "Finance Department"},
            "core": {"cidr": "10.10.10.0/24", "color": "#e74c3c", "description": "Core Network"},
            "dmz": {"cidr": "10.0.0.0/24", "color": "#1abc9c", "description": "Demilitarized Zone"},
            "edge": {"cidr": "203.0.113.0/24", "color": "#7f8c8d", "description": "Edge Network"},
            "external": {"cidr": "0.0.0.0/0", "color": "#bdc3c7", "description": "External Network/Internet"}
        }

        # Initialize default ACL rules
        st.session_state.network_data["acl_rules"] = [
            {"src": "Any", "dst": "DNS-Server", "port": "53", "proto": "Any", "action": "Allow"},
            {"src": "Any", "dst": "Web-Server", "port": "80,443", "proto": "TCP", "action": "Allow"},
            {"src": "Any", "dst": "Mail-Server", "port": "25,110,143", "proto": "TCP", "action": "Allow"},
            {"src": "HR-PC1", "dst": "HR-Server", "port": "Any", "proto": "Any", "action": "Allow"},
            {"src": "Finance-PC1", "dst": "Finance-Server", "port": "Any", "proto": "Any", "action": "Allow"},
            {"src": "Any", "dst": "Internet", "port": "Any", "proto": "Any", "action": "Allow"}
        ]
        
        # Set up initial threat intelligence data
        st.session_state.network_data["threat_intel"] = {
            "malicious_ips": ["45.55.32.10", "103.242.133.7", "185.176.27.132", "91.92.103.137"],
            "known_signatures": {
                "sql_injection": r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                "xss": r"(<script>)|(<img[^>]+\bon[a-z]+\s*=)|(\balert\s*\()|(\beval\s*\()",
                "command_injection": r"(;.*\b(ping|ls|cat|rm|chmod)\b)|(\|.*\b(ping|ls|cat|rm|chmod)\b)",
                "port_scan": r"multiple connections to different ports in short time"
            },
            "threat_categories": {
                "botnet": ["103.242.133.7"],
                "ransomware": ["185.176.27.132"],
                "phishing": ["91.92.103.137"],
                "malware": ["45.55.32.10"]
            }
        }
        
        logger.info(f"Initialized default network configuration")
        
    except Exception as e:
        logger.error(f"Error in default_config: {str(e)}")
        st.error(f"Error setting up default configuration: {str(e)}")

# Modify the draw_network function to include better error handling
def draw_network(highlight_path=None, animation_data=None):
    """Draw network topology with Plotly"""
    try:
        if not st.session_state.network_data.get("devices"):
            st.error("Network devices not found. Initializing default network.")
            default_config()
            
        devices = st.session_state.network_data["devices"]
        connections = st.session_state.network_data["connections"]
        
        if not devices or not connections:
            st.error("Empty network configuration detected.")
            return go.Figure()
        
        G = nx.Graph()
        for node, details in devices.items():
            G.add_node(node, subnet=details["subnet"], device_type=details["type"], status=details.get("status", "normal"))
        
        for a, b in connections:
            G.add_edge(a, b)
        
        # Use spring layout but adjust node positions based on subnet
        pos = nx.spring_layout(G, seed=42)
        
        # Adjust positions by subnet for better network segment visualization
        subnet_groups = {}
        for node, details in devices.items():
            subnet = details["subnet"]
            if subnet not in subnet_groups:
                subnet_groups[subnet] = []
            subnet_groups[subnet].append(node)
        
        # Calculate subnet centers with fixed positions for consistent layout
        subnet_centers = {
            "hr": (-1.5, -1.0),
            "finance": (-1.5, 1.0),
            "core": (0, 0),
            "dmz": (1.5, 0),
            "edge": (3.0, 0),
            "external": (4.5, 0),
        }
        
        # Adjust node positions based on their subnet centers
        for node, (x, y) in pos.items():
            subnet = devices[node]["subnet"]
            center_x, center_y = subnet_centers.get(subnet, (0, 0))
            
            # Group nodes within their subnet, but maintain some separation
            n_nodes_in_subnet = len(subnet_groups[subnet])
            node_idx = subnet_groups[subnet].index(node)
            
            # Calculate position within subnet
            if n_nodes_in_subnet > 1:
                node_offset_x = 0.3 * np.cos(2 * np.pi * node_idx / n_nodes_in_subnet)
                node_offset_y = 0.3 * np.sin(2 * np.pi * node_idx / n_nodes_in_subnet)
            else:
                node_offset_x, node_offset_y = 0, 0
            
            pos[node] = (center_x + node_offset_x, center_y + node_offset_y)
        
        # Create figure with the right background color based on settings
        bg_color = "rgba(240, 240, 240, 0.8)"
        if st.session_state.network_data.get("display_settings", {}).get("dark_mode", False):
            bg_color = "rgba(25, 25, 25, 0.8)"
        
        fig = go.Figure()
        
        # Add subnet regions as colored backgrounds
        for subnet, details in st.session_state.network_data["subnets"].items():
            if subnet in subnet_centers:
                center_x, center_y = subnet_centers[subnet]
                subnet_nodes = [node for node, node_details in devices.items() 
                                if node_details["subnet"] == subnet]
                
                if subnet_nodes:
                    # Calculate subnet boundary with some padding
                    padding = 0.4
                    min_x = min([pos[node][0] for node in subnet_nodes]) - padding
                    max_x = max([pos[node][0] for node in subnet_nodes]) + padding
                    min_y = min([pos[node][1] for node in subnet_nodes]) - padding
                    max_y = max([pos[node][1] for node in subnet_nodes]) + padding
                    
                    # Add a colored rectangle for the subnet
                    subnet_color = details["color"]
                    # Make it slightly transparent
                    subnet_color_rgba = f"rgba({int(subnet_color[1:3], 16)}, {int(subnet_color[3:5], 16)}, {int(subnet_color[5:7], 16)}, 0.2)"
                    
                    fig.add_shape(
                        type="rect",
                        x0=min_x, y0=min_y, x1=max_x, y1=max_y,
                        fillcolor=subnet_color_rgba,
                        line=dict(color=subnet_color, width=1),
                        layer="below"
                    )
        
        # Add edges first (so they're under nodes)
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            color = 'gray'
            width = 2
            
            # Check if this edge is part of the highlighted path
            if highlight_path and (edge in highlight_path or (edge[1], edge[0]) in highlight_path):
                color = 'red'
                width = 4
            
            fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], line=dict(width=width, color=color),
                                     mode='lines', hoverinfo='none'))
        
        # Add animation dots if provided
        show_animations = st.session_state.network_data.get("display_settings", {}).get("show_animations", True)
        if animation_data and show_animations:
            src, dst, result = animation_data.get("src"), animation_data.get("dst"), animation_data.get("result")
            
            if src and dst and src in pos and dst in pos:
                # Get the source and destination positions
                src_x, src_y = pos[src]
                dst_x, dst_y = pos[dst]
                
                # Calculate points along the path for animation
                num_points = 10
                x_points = np.linspace(src_x, dst_x, num_points)
                y_points = np.linspace(src_y, dst_y, num_points)
                
                # Add dots representing packet movement
                dot_color = "green" if result == "Allowed" else "red"
                
                for i in range(num_points):
                    # Make the dots fade as they move along the path
                    opacity = 1.0 if i == num_points - 1 else 0.5
                    size = 10 if i == num_points - 1 else 8
                    
                    fig.add_trace(go.Scatter(
                        x=[x_points[i]], y=[y_points[i]],
                        mode='markers',
                        marker=dict(size=size, color=dot_color, opacity=opacity),
                        showlegend=False,
                        hoverinfo='none'
                    ))
                
                # Add a block symbol if the packet was blocked
                if result == "Blocked":
                    # Find the middle point along the path
                    mid_x = (src_x + dst_x) / 2
                    mid_y = (src_y + dst_y) / 2
                    
                    fig.add_trace(go.Scatter(
                        x=[mid_x], y=[mid_y],
                        mode='markers',
                        marker=dict(
                            size=16, 
                            color="red",
                            symbol="x",
                            line=dict(width=2, color="white")
                        ),
                        showlegend=False,
                        hoverinfo='none'
                    ))
        
        # Add nodes
        for node, details in devices.items():
            x, y = pos[node]
            subnet = details["subnet"]
            subnet_color = st.session_state.network_data["subnets"][subnet]["color"]
            
            # Adjust node appearance based on status
            node_opacity = 1.0
            border_width = 1
            border_color = "black"
            
            if details.get("status") == "compromised":
                border_color = "red"
                border_width = 2
            elif details.get("status") == "warning":
                border_color = "orange"
                border_width = 2
            elif details.get("status") == "down":
                node_opacity = 0.5
            
            # Create hover text with detailed information
            hover_text = (
                f"<b>{node}</b><br>"
                f"IP: {details['ip']}<br>"
                f"Type: {details['type']}<br>"
                f"Subnet: {subnet} ({st.session_state.network_data['subnets'][subnet]['cidr']})<br>"
                f"Status: {details.get('status', 'normal')}"
            )
            
            # Show node labels if enabled
            show_labels = st.session_state.network_data.get("display_settings", {}).get("show_labels", True)
            
            fig.add_trace(go.Scatter(
                x=[x], y=[y], 
                text=[f"{icons[details['type']]} {node}"] if show_labels else None,
                hovertext=[hover_text],
                mode='markers+text' if show_labels else 'markers',
                marker=dict(
                    size=40, 
                    color=subnet_color, 
                    line=dict(color=border_color, width=border_width),
                    opacity=node_opacity
                ),
                textposition="bottom center"
            ))
        
        # Add subnet labels
        if st.session_state.network_data.get("display_settings", {}).get("show_labels", True):
            for subnet, details in st.session_state.network_data["subnets"].items():
                if subnet in subnet_centers:
                    center_x, center_y = subnet_centers[subnet]
                    
                    # Position the label above the subnet
                    label_y_offset = 0.5
                    
                    fig.add_annotation(
                        x=center_x, y=center_y + label_y_offset,
                        text=f"{subnet.upper()} ({details['cidr']})",
                        showarrow=False,
                        font=dict(
                            size=14, 
                            color="black" if not st.session_state.network_data.get("display_settings", {}).get("dark_mode", False) else "white"
                        )
                    )
        
        # Set layout properties
        text_color = "black" if not st.session_state.network_data.get("display_settings", {}).get("dark_mode", False) else "white"
        
        fig.update_layout(
            showlegend=False,
            hovermode='closest',
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor=bg_color,
            paper_bgcolor=bg_color,
            font=dict(color=text_color)
        )
        
        # Return the figure instead of immediately plotting
        return fig
    except Exception as e:
        logger.error(f"Error drawing network: {str(e)}")
        st.error(f"Error visualizing network: {str(e)}")
        # Return an empty figure on error
        return go.Figure()

def initialize_models():
    """Initialize different machine learning models for comparison"""
    try:
        if not st.session_state.network_data["models"]:
            st.session_state.network_data["models"] = {
                "sgd": SGDClassifier(loss="log_loss", max_iter=1000, tol=1e-3, random_state=42),
                "random_forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
                "gradient_boost": GradientBoostingClassifier(n_estimators=100, random_state=42),
                "neural_net": MLPClassifier(hidden_layer_sizes=(50, 25), max_iter=1000, random_state=42),
                "ensemble": None  # Will be handled specially
            }
        
        # Initialize with expanded sample data if none exists
        if not st.session_state.network_data["training_data"]["X"]:
            # Create more diverse training data
            X_train = np.array([
                # Format: [src_ip_last_octet, dst_ip_last_octet, port, proto, size, hour_of_day, is_weekend]
                # Normal traffic patterns
                [10, 53, 53, 17, 100, 14, 0],  # DNS query
                [11, 80, 80, 6, 500, 10, 0],   # HTTP traffic
                [12, 27, 3306, 6, 300, 15, 0], # Database access
                [13, 80, 443, 6, 800, 16, 0],  # HTTPS traffic
                [10, 8, 80, 6, 1200, 20, 1],   # Web browsing
                [11, 8, 443, 6, 300, 22, 1],   # Secure browsing 
                [10, 53, 53, 17, 100, 9, 1],   # More DNS
                [12, 27, 3306, 6, 400, 11, 0], # More DB
                [13, 25, 25, 6, 550, 13, 0],   # Email (SMTP)
                [10, 25, 25, 6, 620, 14, 0],   # More Email
                [11, 110, 110, 6, 300, 15, 0], # POP3
                [12, 80, 80, 6, 1100, 16, 1],  # More HTTP
                [13, 443, 443, 6, 950, 17, 1], # More HTTPS
                [10, 53, 53, 17, 80, 18, 0],   # More DNS
                
                # Abnormal patterns (attacks)
                [99, 80, 80, 6, 60, 3, 0],     # Port scan (small packets, unusual hour)
                [98, 25, 25, 6, 5000, 4, 0],   # Email flooding
                [97, 80, 1434, 6, 150, 2, 1],  # SQL port probe
                [96, 53, 53, 17, 4000, 1, 1],  # DNS amplification
                [95, 80, 80, 6, 7000, 23, 0],  # HTTP flood
                [94, 443, 443, 6, 8000, 22, 0],# HTTPS flood
                [93, 22, 22, 6, 300, 3, 1],    # SSH brute force attempt
                [92, 3389, 3389, 6, 400, 2, 1],# RDP brute force attempt
                [91, 25, 25, 6, 9000, 4, 0],   # More email flooding
                [90, 80, 21, 6, 150, 3, 1],    # FTP probing
                [89, 27, 1433, 6, 200, 2, 0],  # SQL injection attempt
                [88, 80, 80, 6, 3500, 1, 0],   # More HTTP flood
            ])
            
            # 1 for normal/allowed traffic, 0 for abnormal/blocked traffic
            y_train = np.array([
                # Normal traffic - allowed
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
                # Abnormal traffic - blocked
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
            
            st.session_state.network_data["training_data"]["X"] = X_train.tolist()
            st.session_state.network_data["training_data"]["y"] = y_train.tolist()
            
            # Train models with initial data
            X_scaled = StandardScaler().fit_transform(X_train)
            for model_name, model in st.session_state.network_data["models"].items():
                if model_name != "ensemble":
                    model.fit(X_scaled, y_train)
            
            logger.info("Initialized ML models with training data")
    except Exception as e:
        logger.error(f"Error in initialize_models: {str(e)}")
        st.error(f"Error initializing models: {str(e)}")

def extract_features(src, dst, port, proto, size):
    """Extract rich feature set from packet information"""
    try:
        # Basic features
        try:
            src_ip = st.session_state.network_data["devices"][src]["ip"]
            dst_ip = st.session_state.network_data["devices"][dst]["ip"]
            src_ip_last = int(src_ip.split('.')[-1])
            dst_ip_last = int(dst_ip.split('.')[-1])
        except:
            src_ip_last = 0
            dst_ip_last = 0
        
        # Time-based features
        current_time = datetime.now()
        hour_of_day = current_time.hour
        is_weekend = 1 if current_time.weekday() >= 5 else 0
        
        # Combine all features
        features = np.array([[src_ip_last, dst_ip_last, port, proto, size, hour_of_day, is_weekend]])
        return features
    except Exception as e:
        logger.error(f"Error extracting features: {str(e)}")
        return np.array([[0, 0, 0, 0, 0, 0, 0]])  # Return default features on error

def calculate_explainability(model, X_scaled):
    """Calculate SHAP values for model explainability"""
    try:
        # For different model types
        if hasattr(model, 'predict_proba'):
            if isinstance(model, RandomForestClassifier) or isinstance(model, GradientBoostingClassifier):
                # Tree-based models
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X_scaled)
                
                # For binary classification, shap_values is a list of arrays (one per class)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # Take the values for the positive class
                
                return {
                    "values": shap_values.tolist(),
                    "base_values": explainer.expected_value if not isinstance(explainer.expected_value, list) 
                                 else explainer.expected_value[1],
                    "model_type": "tree"
                }
            else:
                # Other models that support prediction probabilities
                explainer = shap.KernelExplainer(model.predict_proba, X_scaled)
                shap_values = explainer.shap_values(X_scaled)
                
                # For binary classification, shap_values is a list of arrays (one per class)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # Take the values for the positive class
                    
                return {
                    "values": shap_values.tolist(),
                    "base_values": explainer.expected_value if not isinstance(explainer.expected_value, list) 
                                 else explainer.expected_value[1],
                    "model_type": "kernel"
                }
        return None
    except Exception as e:
        logger.error(f"Error calculating explainability: {str(e)}")
        return None

def find_path(src, dst):
    """Find a path between source and destination nodes in the network"""
    try:
        # Create a graph of the network
        G = nx.Graph()
        for a, b in st.session_state.network_data["connections"]:
            G.add_edge(a, b)
        
        # Use Dijkstra's algorithm to find shortest path
        if nx.has_path(G, src, dst):
            path = nx.shortest_path(G, source=src, target=dst)
            
            # Convert path to list of edges
            path_edges = []
            for i in range(len(path) - 1):
                path_edges.append((path[i], path[i + 1]))
            
            return path_edges
        else:
            logger.warning(f"No path found between {src} and {dst}")
            return []
    except Exception as e:
        logger.error(f"Error finding path: {str(e)}")
        return []

def apply_acl_rules(src, dst, port, proto):
    """Apply ACL rules to determine if traffic should be allowed or blocked"""
    try:
        rules = st.session_state.network_data["acl_rules"]
        
        # First check if there's a specific rule that matches
        for rule in rules:
            src_match = rule["src"] == "Any" or rule["src"] == src
            dst_match = rule["dst"] == "Any" or rule["dst"] == dst
            
            # Handle port matching (ranges, lists, any)
            port_match = False
            if rule["port"] == "Any":
                port_match = True
            else:
                # Handle comma-separated port lists
                if "," in rule["port"]:
                    port_list = [int(p.strip()) for p in rule["port"].split(",")]
                    port_match = port in port_list
                # Handle port ranges with dash
                elif "-" in rule["port"]:
                    port_range = rule["port"].split("-")
                    min_port = int(port_range[0].strip())
                    max_port = int(port_range[1].strip())
                    port_match = min_port <= port <= max_port
                # Single port
                else:
                    try:
                        rule_port = int(rule["port"])
                        port_match = port == rule_port
                    except:
                        # If port isn't a valid integer, assume no match
                        port_match = False
            
            # Handle protocol matching
            proto_match = rule["proto"] == "Any" or (
                rule["proto"] == "TCP" and proto == 6 or
                rule["proto"] == "UDP" and proto == 17
            )
            
            # If all criteria match, apply the rule
            if src_match and dst_match and port_match and proto_match:
                return rule["action"] == "Allow"
        
        # Default policy if no rules match (default allow)
        return True
    except Exception as e:
        logger.error(f"Error applying ACL rules: {str(e)}")
        # On error, default to blocking for safety
        return False

def check_against_threat_intel(src, dst, port, proto, payload_size):
    """Check if the traffic matches known threats in threat intelligence"""
    try:
        threat_intel = st.session_state.network_data["threat_intel"]
        devices = st.session_state.network_data["devices"]
        
        # Extract IPs
        src_ip = devices.get(src, {}).get("ip", "")
        dst_ip = devices.get(dst, {}).get("ip", "")
        
        # Check against malicious IPs
        if src_ip in threat_intel["malicious_ips"] or dst_ip in threat_intel["malicious_ips"]:
            threat_type = "Unknown"
            for category, ips in threat_intel["threat_categories"].items():
                if src_ip in ips or dst_ip in ips:
                    threat_type = category
                    break
            
            return {
                "detected": True,
                "type": f"Known malicious IP ({threat_type})",
                "confidence": 0.95,
                "details": f"IP address {'source' if src_ip in threat_intel['malicious_ips'] else 'destination'} matches known threat intelligence"
            }
        
        # Check for port scan pattern
        # In a real system, this would be more sophisticated with state tracking
        recent_traffic = st.session_state.network_data["traffic_log"][-10:] if st.session_state.network_data["traffic_log"] else []
        src_ports_count = len(set([log["port"] for log in recent_traffic if log["src"] == src]))
        
        if src_ports_count >= 5:  # If same source tried 5+ different ports recently
            return {
                "detected": True,
                "type": "Port Scan",
                "confidence": 0.8,
                "details": f"Source {src} attempted connections to multiple ports in short succession"
            }
        
        # Check for DDoS patterns (high volume from same source)
        src_traffic_volume = sum([log["size"] for log in recent_traffic if log["src"] == src])
        if src_traffic_volume > 20000:  # Arbitrary threshold for demonstration
            return {
                "detected": True,
                "type": "DDoS/DoS Attack",
                "confidence": 0.85,
                "details": f"High traffic volume ({src_traffic_volume} bytes) from source {src}"
            }
        
        # No threats detected
        return {
            "detected": False,
            "type": None,
            "confidence": 0,
            "details": None
        }
    except Exception as e:
        logger.error(f"Error checking threat intelligence: {str(e)}")
        return {"detected": False, "type": None, "confidence": 0, "details": None}

def make_prediction(src, dst, port, proto, size):
    """Make a prediction using the active model and ACL rules"""
    try:
        # First check against ACL rules
        acl_result = apply_acl_rules(src, dst, port, proto)
        
        # Then check against threat intelligence
        threat_check = check_against_threat_intel(src, dst, port, proto, size)
        
        # Extract features for ML prediction
        features = extract_features(src, dst, port, proto, size)
        
        # Normalize features
        scaler = StandardScaler()
        
        # Get training data for scaling
        X_train = np.array(st.session_state.network_data["training_data"]["X"])
        y_train = np.array(st.session_state.network_data["training_data"]["y"])
        
        # Fit scaler on all available data
        scaler.fit(X_train)
        X_scaled = scaler.transform(features)
        
        # Get the active model
        active_model_name = st.session_state.network_data["active_model"]
        
        # Make prediction with the selected model
        if active_model_name == "ensemble":
            # For ensemble, average predictions from all models
            probas = []
            for model_name, model in st.session_state.network_data["models"].items():
                if model_name != "ensemble":
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(X_scaled)[0][1]  # Probability of class 1
                        probas.append(proba)
            
            avg_proba = sum(probas) / len(probas)
            ml_prediction = 1 if avg_proba > 0.5 else 0
            confidence = max(avg_proba, 1-avg_proba)
        else:
            # Use the selected model
            model = st.session_state.network_data["models"][active_model_name]
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(X_scaled)[0][1]
                ml_prediction = 1 if proba > 0.5 else 0
                confidence = max(proba, 1-proba)
            else:
                ml_prediction = model.predict(X_scaled)[0]
                confidence = 0.95  # Default confidence if not available
        
        # Get explainability
        if active_model_name != "ensemble":
            shap_values = calculate_explainability(
                st.session_state.network_data["models"][active_model_name], 
                X_scaled
            )
        else:
            shap_values = None
        
        # Now combine all results into a final decision
        # If ACL blocks or threat intel detects an issue, block regardless of ML
        if not acl_result or threat_check["detected"]:
            final_prediction = 0  # Block
            if not acl_result:
                reason = "ACL Rule"
                details = "Traffic blocked by Access Control List"
                final_confidence = 1.0  # ACL rules are deterministic
            else:
                reason = "Threat Intelligence"
                details = threat_check["details"]
                final_confidence = threat_check["confidence"]
        else:
            # Otherwise use the ML prediction
            final_prediction = ml_prediction
            reason = "ML Model"
            details = f"Prediction made by {active_model_name} model"
            final_confidence = confidence
        
        result = "Allowed" if final_prediction == 1 else "Blocked"
        
        # Find the path through the network
        path = find_path(src, dst) if result == "Allowed" else []
        
        # Create a detailed record
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        details = {
            "src": src,
            "dst": dst,
            "port": port,
            "proto": proto,
            "size": size,
            "features": features.tolist(),
            "ml_prediction": ml_prediction,
            "acl_result": acl_result,
            "threat_check": threat_check,
            "final_prediction": final_prediction,
            "confidence": final_confidence,
            "result": result,
            "reason": reason,
            "model": active_model_name,
            "timestamp": timestamp,
            "shap_values": shap_values,
            "path": path
        }
        
        # Add to traffic log
        st.session_state.network_data["traffic_log"].append(details)
        
        # Store the last packet for training
        st.session_state.network_data["last_packet"] = details
        
        # Add to timeline
        st.session_state.network_data["timeline_events"].append({
            "timestamp": timestamp,
            "event_type": "traffic",
            "result": result,
            "details": details
        })
        
        # If it's a security event, add to security events log
        if result == "Blocked" or threat_check["detected"]:
            event_type = threat_check["type"] if threat_check["detected"] else "Suspicious Traffic"
            st.session_state.network_data["security_events"].append({
                "timestamp": timestamp,
                "type": event_type,
                "details": details,
                "detected": True
            })
            
            # Add to timeline as security event
            st.session_state.network_data["timeline_events"].append({
                "timestamp": timestamp,
                "event_type": "security",
                "result": "detected",
                "details": details
            })
        
        return result, final_confidence, details
    except Exception as e:
        logger.error(f"Error in make_prediction: {str(e)}\n{traceback.format_exc()}")
        # Default to blocking on error for safety
        return "Error (Blocked for safety)", 1.0, {"error": str(e)}

def train_model(label):
    """Train the model with the last packet"""
    try:
        if st.session_state.network_data["last_packet"]:
            features = st.session_state.network_data["last_packet"]["features"]
            
            # Add to training data
            X_train = np.array(st.session_state.network_data["training_data"]["X"])
            y_train = np.array(st.session_state.network_data["training_data"]["y"])
            
            X_train = np.vstack([X_train, features])
            y_train = np.append(y_train, label)
            
            st.session_state.network_data["training_data"]["X"] = X_train.tolist()
            st.session_state.network_data["training_data"]["y"] = y_train.tolist()
            
            # Train all models
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_train)
            
            for model_name, model in st.session_state.network_data["models"].items():
                if model_name != "ensemble":
                    model.fit(X_scaled, y_train)
            
            # Add the training event to the timeline
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            st.session_state.network_data["timeline_events"].append({
                "timestamp": timestamp,
                "event_type": "training",
                "result": "Allowed" if label == 1 else "Blocked",
                "details": {
                    "packet": st.session_state.network_data["last_packet"],
                    "user_label": label
                }
            })
            
            logger.info(f"Model trained with new example, label={label}")
            return True
        return False
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        return False

def generate_synthetic_training_data(n_samples=50):
    """Generate synthetic training data to augment the existing dataset"""
    try:
        # Get existing data
        X_train = np.array(st.session_state.network_data["training_data"]["X"])
        y_train = np.array(st.session_state.network_data["training_data"]["y"])
        
        # Get statistics of existing data
        normal_samples = X_train[y_train == 1]
        abnormal_samples = X_train[y_train == 0]
        
        # Generate new samples based on the distribution of existing ones
        new_samples_X = []
        new_samples_y = []
        
        # Add normal samples with variations
        for _ in range(n_samples // 2):
            if len(normal_samples) > 0:
                # Select a random normal sample to base the new one on
                base_sample = normal_samples[np.random.randint(0, len(normal_samples))]
                
                # Add some random variations
                new_sample = base_sample.copy()
                
                # Randomly modify some features
                feature_to_modify = np.random.randint(0, len(base_sample))
                
                # Different modifications based on which feature
                if feature_to_modify == 0 or feature_to_modify == 1:  # IP octets
                    new_sample[feature_to_modify] = max(1, min(254, base_sample[feature_to_modify] + np.random.randint(-5, 6)))
                elif feature_to_modify == 2:  # Port
                    common_ports = [80, 443, 53, 22, 25, 110, 143, 3306, 3389]
                    new_sample[feature_to_modify] = np.random.choice(common_ports)
                elif feature_to_modify == 3:  # Protocol
                    new_sample[feature_to_modify] = np.random.choice([6, 17])  # TCP or UDP
                elif feature_to_modify == 4:  # Size
                    new_sample[feature_to_modify] = max(50, min(5000, base_sample[feature_to_modify] + np.random.randint(-200, 201)))
                elif feature_to_modify == 5:  # Hour of day
                    new_sample[feature_to_modify] = np.random.randint(8, 20)  # Business hours
                elif feature_to_modify == 6:  # Is weekend
                    new_sample[feature_to_modify] = np.random.choice([0, 1])
                    
                new_samples_X.append(new_sample)
                new_samples_y.append(1)  # Normal traffic
        
        # Add abnormal samples with variations
        for _ in range(n_samples - len(new_samples_X)):
            if len(abnormal_samples) > 0:
                # Select a random abnormal sample to base the new one on
                base_sample = abnormal_samples[np.random.randint(0, len(abnormal_samples))]
                
                # Add some random variations
                new_sample = base_sample.copy()
                
                # Randomly modify some features
                feature_to_modify = np.random.randint(0, len(base_sample))
                
                # Different modifications based on which feature
                if feature_to_modify == 0 or feature_to_modify == 1:  # IP octets
                    new_sample[feature_to_modify] = max(1, min(254, base_sample[feature_to_modify] + np.random.randint(-5, 6)))
                elif feature_to_modify == 2:  # Port
                    suspicious_ports = [1433, 445, 135, 139, 4444, 31337]
                    new_sample[feature_to_modify] = np.random.choice(suspicious_ports)
                elif feature_to_modify == 3:  # Protocol
                    new_sample[feature_to_modify] = np.random.choice([6, 17])  # TCP or UDP
                elif feature_to_modify == 4:  # Size
                    # Abnormal sizes - very small (port scan) or very large (DoS)
                    if np.random.random() < 0.5:
                        new_sample[feature_to_modify] = np.random.randint(20, 100)  # Small packets for scan
                    else:
                        new_sample[feature_to_modify] = np.random.randint(6000, 10000)  # Large packets for DoS
                elif feature_to_modify == 5:  # Hour of day
                    new_sample[feature_to_modify] = np.random.randint(0, 7)  # Late night hours
                elif feature_to_modify == 6:  # Is weekend
                    new_sample[feature_to_modify] = np.random.choice([0, 1])
                
                new_samples_X.append(new_sample)
                new_samples_y.append(0)  # Abnormal traffic
        
        # Combine with existing training data
        if new_samples_X:
            new_X = np.vstack([X_train, np.array(new_samples_X)])
            new_y = np.append(y_train, new_samples_y)
            
            st.session_state.network_data["training_data"]["X"] = new_X.tolist()
            st.session_state.network_data["training_data"]["y"] = new_y.tolist()
            
            # Retrain all models with the new data
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(new_X)
            
            for model_name, model in st.session_state.network_data["models"].items():
                if model_name != "ensemble":
                    model.fit(X_scaled, new_y)
            
            logger.info(f"Generated {len(new_samples_X)} synthetic training samples")
            return len(new_samples_X)
        
        return 0
    except Exception as e:
        logger.error(f"Error generating synthetic data: {str(e)}")
        return 0

def simulate_attack(attack_type=None):
    """Simulate a common network attack"""
    try:
        attack_types = [
            {"name": "Port Scan", "src": "HR-PC1", "dst": "Web-Server", "ports": [21, 22, 23, 25, 80, 443], "proto": 6, "size": 60},
            {"name": "DoS", "src": "Finance-PC2", "dst": "Web-Server", "ports": [80], "proto": 6, "size": 8500},
            {"name": "Data Exfiltration", "src": "HR-PC1", "dst": "Internet", "ports": [443], "proto": 6, "size": 7000},
            {"name": "Brute Force", "src": "Web-Server", "dst": "Finance-Server", "ports": [22], "proto": 6, "size": 300},
            {"name": "SQL Injection", "src": "HR-PC2", "dst": "Finance-Server", "ports": [3306], "proto": 6, "size": 800},
            {"name": "Cross-Site Scripting", "src": "HR-PC2", "dst": "Web-Server", "ports": [80], "proto": 6, "size": 1200},
            {"name": "Lateral Movement", "src": "Finance-PC2", "dst": "HR-Server", "ports": [445], "proto": 6, "size": 1800}
        ]
        
        # Select an attack type if not specified
        if attack_type is None:
            attack = random.choice(attack_types)
        else:
            # Find the specified attack type
            attack = next((a for a in attack_types if a["name"] == attack_type), random.choice(attack_types))
        
        # Check if source and destination exist in the current network
        devices = st.session_state.network_data["devices"]
        if attack["src"] not in devices or attack["dst"] not in devices:
            # Find alternative devices
            pc_devices = [name for name, details in devices.items() if details["type"] == "pc"]
            server_devices = [name for name, details in devices.items() if details["type"] in ["server", "database"]]
            
            if pc_devices and server_devices:
                attack["src"] = random.choice(pc_devices)
                attack["dst"] = random.choice(server_devices)
            else:
                # Fallback to HR-PC1 and Web-Server if they exist
                attack["src"] = "HR-PC1" if "HR-PC1" in devices else list(devices.keys())[0]
                attack["dst"] = "Web-Server" if "Web-Server" in devices else list(devices.keys())[-1]
        
        results = []
        
        # Update the status of the source device to indicate it might be compromised
        if attack["src"] in devices:
            devices[attack["src"]]["status"] = "compromised"
        
        # Add a timeline event for the start of the attack
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        st.session_state.network_data["timeline_events"].append({
            "timestamp": timestamp,
            "event_type": "attack_start",
            "result": "initiated",
            "details": {
                "attack_name": attack["name"],
                "attack_src": attack["src"],
                "attack_dst": attack["dst"]
            }
        })
        
        # Execute the attack sequence
        for port in attack["ports"]:
            result, confidence, details = make_prediction(
                attack["src"], attack["dst"], port, attack["proto"], attack["size"]
            )
            
            results.append({
                "packet": details,
                "detected": result == "Blocked",
                "confidence": confidence
            })
            
            # Small delay to simulate real traffic
            time.sleep(0.1)
        
        # Add attack conclusion to timeline
        detected_count = sum(1 for r in results if r["detected"])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        detection_effectiveness = detected_count / len(results) if results else 0
        
        st.session_state.network_data["timeline_events"].append({
            "timestamp": timestamp,
            "event_type": "attack_end",
            "result": f"detected {detected_count}/{len(results)}" if results else "no_packets",
            "details": {
                "attack_name": attack["name"],
                "detection_rate": f"{detection_effectiveness:.2%}",
                "packets": len(results)
            }
        })
        
        # Reset the status of affected devices after some time
        if attack["src"] in devices:
            # In a real implementation, you would set a timer to reset this later
            # For now, we'll leave it compromised for demonstration purposes
            pass
        
        logger.info(f"Simulated {attack['name']} attack: {detected_count}/{len(results)} packets detected")
        return attack["name"], results
    except Exception as e:
        logger.error(f"Error simulating attack: {str(e)}")
        return "Error", []

def simulate_normal_traffic():
    """Simulate normal network traffic"""
    try:
        devices = st.session_state.network_data["devices"]
        
        # Define possible normal flows based on network topology
        normal_flows = []
        
        # Find all PC devices
        pc_devices = [name for name, details in devices.items() if details["type"] == "pc"]
        server_devices = [name for name, details in devices.items() if details["type"] in ["server", "database"]]
        internet = "Internet" if "Internet" in devices else None
        
        # Create flows from PCs to servers and internet
        for pc in pc_devices:
            # PC to DNS server
            dns_servers = [s for s in server_devices if "DNS" in s]
            if dns_servers:
                normal_flows.append({"src": pc, "dst": dns_servers[0], "port": 53, "proto": 17, "size": random.randint(80, 150)})
            
            # PC to web server
            web_servers = [s for s in server_devices if "Web" in s]
            if web_servers:
                normal_flows.append({"src": pc, "dst": web_servers[0], "port": 80, "proto": 6, "size": random.randint(300, 1200)})
                normal_flows.append({"src": pc, "dst": web_servers[0], "port": 443, "proto": 6, "size": random.randint(300, 1200)})
            
            # PC to mail server
            mail_servers = [s for s in server_devices if "Mail" in s]
            if mail_servers:
                normal_flows.append({"src": pc, "dst": mail_servers[0], "port": 25, "proto": 6, "size": random.randint(200, 600)})
            
            # PC to internet
            if internet:
                normal_flows.append({"src": pc, "dst": internet, "port": 80, "proto": 6, "size": random.randint(500, 2000)})
                normal_flows.append({"src": pc, "dst": internet, "port": 443, "proto": 6, "size": random.randint(500, 2000)})
        
        # If we couldn't build flows based on the topology, fall back to some default ones
        if not normal_flows:
            normal_flows = [
                {"src": "HR-PC1", "dst": "DNS-Server", "port": 53, "proto": 17, "size": 100},
                {"src": "Finance-PC2", "dst": "Web-Server", "port": 80, "proto": 6, "size": 500},
                {"src": "Eng-PC3", "dst": "Mail-Server", "port": 25, "proto": 6, "size": 200},
                {"src": "Guest-PC1", "dst": "Internet", "port": 443, "proto": 6, "size": 800}
            ]
        
        # Select a subset of flows to simulate
        num_flows = min(len(normal_flows), random.randint(2, 5))
        selected_flows = random.sample(normal_flows, num_flows)
        
        results = []
        for flow in selected_flows:
            # Verify source and destination exist
            if flow["src"] in devices and flow["dst"] in devices:
                result, confidence, details = make_prediction(
                    flow["src"], flow["dst"], flow["port"], flow["proto"], flow["size"]
                )
                
                results.append({
                    "flow": flow,
                    "result": result,
                    "confidence": confidence,
                    "details": details
                })
                
                # Small delay to simulate real traffic
                time.sleep(0.05)
        
        logger.info(f"Simulated {len(results)} normal traffic flows")
        return results
    except Exception as e:
        logger.error(f"Error simulating normal traffic: {str(e)}")
        return []

def update_traffic_stats():
    """Update traffic statistics"""
    try:
        logs = st.session_state.network_data["traffic_log"]
        if logs:
            # Count packets by result
            allowed = sum(1 for log in logs if log["result"] == "Allowed")
            blocked = sum(1 for log in logs if log["result"] == "Blocked")
            
            # Count packets by protocol
            tcp = sum(1 for log in logs if log["proto"] == 6)
            udp = sum(1 for log in logs if log["proto"] == 17)
            
            # Traffic volume
            total_bytes = sum(log["size"] for log in logs)
            
            # Count by source
            by_source = {}
            for log in logs:
                src = log["src"]
                by_source[src] = by_source.get(src, 0) + 1
            
            # Count by destination
            by_dest = {}
            for log in logs:
                dst = log["dst"]
                by_dest[dst] = by_dest.get(dst, 0) + 1
            
            # Count by port
            by_port = {}
            for log in logs:
                port = log["port"]
                by_port[port] = by_port.get(port, 0) + 1
            
            # Count by reason (ML, ACL, Threat Intel)
            by_reason = {}
            for log in logs:
                reason = log.get("reason", "Unknown")
                by_reason[reason] = by_reason.get(reason, 0) + 1
            
            # Traffic over time (last hour)
            current_time = datetime.now()
            hour_ago = current_time - timedelta(hours=1)
            
            time_series = []
            for log in logs:
                try:
                    log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                    if log_time >= hour_ago:
                        time_series.append({
                            "timestamp": log_time,
                            "bytes": log["size"],
                            "result": log["result"]
                        })
                except:
                    pass
            
            # Sort by timestamp
            time_series.sort(key=lambda x: x["timestamp"])
            
            # Calculate detection rate
            detection_rate = blocked / (allowed + blocked) if (allowed + blocked) > 0 else 0
            
            st.session_state.network_data["traffic_stats"] = {
                "allowed": allowed,
                "blocked": blocked,
                "tcp": tcp,
                "udp": udp,
                "total_bytes": total_bytes,
                "by_source": by_source,
                "by_dest": by_dest,
                "by_port": by_port,
                "by_reason": by_reason,
                "time_series": time_series,
                "detection_rate": detection_rate
            }
    except Exception as e:
        logger.error(f"Error updating traffic stats: {str(e)}")

def evaluate_model_performance():
    """Evaluate model performance metrics"""
    try:
        if st.session_state.network_data["traffic_log"]:
            # Get actual results and predictions for packets where we have ground truth
            y_true = []
            y_pred = {}
            X_test = []
            
            for model_name in st.session_state.network_data["models"]:
                if model_name != "ensemble":
                    y_pred[model_name] = []
            
            # Extract from traffic log where we have ground truth
            for log in st.session_state.network_data["traffic_log"]:
                if "actual_label" in log:
                    y_true.append(log["actual_label"])
                    X_test.append(log["features"])
                    
                    for model_name in st.session_state.network_data["models"]:
                        if model_name != "ensemble":
                            # Make prediction with this model
                            model = st.session_state.network_data["models"][model_name]
                            features = np.array(log["features"])
                            scaler = StandardScaler()
                            X_train = np.array(st.session_state.network_data["training_data"]["X"])
                            scaler.fit(X_train)
                            X_scaled = scaler.transform(features.reshape(1, -1))
                            pred = model.predict(X_scaled)[0]
                            y_pred[model_name].append(pred)
            
            # Only proceed if we have ground truth
            if y_true and X_test:
                X_test = np.array(X_test)
                results = {}
                
                for model_name, preds in y_pred.items():
                    if len(preds) > 0:
                        # Calculate metrics
                        cm = confusion_matrix(y_true, preds)
                        report = classification_report(y_true, preds, output_dict=True)
                        accuracy = accuracy_score(y_true, preds)
                        
                        # Get precision-recall curve data for visualization
                        model = st.session_state.network_data["models"][model_name]
                        if hasattr(model, 'predict_proba'):
                            scaler = StandardScaler()
                            X_train = np.array(st.session_state.network_data["training_data"]["X"])
                            scaler.fit(X_train)
                            X_scaled = scaler.transform(X_test)
                            
                            y_scores = model.predict_proba(X_scaled)[:, 1]
                            precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
                            
                            pr_curve = {
                                "precision": precision.tolist(),
                                "recall": recall.tolist(),
                                "thresholds": thresholds.tolist() if len(thresholds) > 0 else []
                            }
                        else:
                            pr_curve = None
                        
                        results[model_name] = {
                            "confusion_matrix": cm.tolist(),
                            "classification_report": report,
                            "accuracy": accuracy,
                            "pr_curve": pr_curve
                        }
                
                return results
            
            return None
        
        return None
    except Exception as e:
        logger.error(f"Error evaluating model performance: {str(e)}")
        return None

def generate_security_report():
    """Generate a comprehensive security report"""
    try:
        # Get current timestamp
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update traffic stats
        update_traffic_stats()
        
        # Evaluate model performance
        model_performance = evaluate_model_performance()
        
        # Collect security events
        security_events = st.session_state.network_data["security_events"]
        
        # Get traffic stats
        traffic_stats = st.session_state.network_data["traffic_stats"]
        
        # Collect timeline events
        timeline_events = st.session_state.network_data["timeline_events"]
        
        # Count attack types
        attack_counts = {}
        for event in security_events:
            attack_type = event.get("type", "Unknown")
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        # Create report object
        report = {
            "timestamp": report_time,
            "summary": {
                "total_packets": len(st.session_state.network_data["traffic_log"]),
                "allowed_packets": traffic_stats.get("allowed", 0),
                "blocked_packets": traffic_stats.get("blocked", 0),
                "security_events": len(security_events),
                "detection_rate": traffic_stats.get("detection_rate", 0),
                "total_traffic_volume": traffic_stats.get("total_bytes", 0),
                "attack_types": attack_counts
            },
            "traffic_analysis": traffic_stats,
            "security_events": [
                {
                    "timestamp": event["timestamp"],
                    "type": event["type"],
                    "detected": event["detected"]
                }
                for event in security_events[-50:] # Last 50 events to keep the report manageable
            ],
            "model_performance": model_performance,
            "recommendations": []
        }
        
        # Generate recommendations based on findings
        if traffic_stats.get("detection_rate", 0) < 0.5:
            report["recommendations"].append({
                "priority": "high",
                "title": "Improve Detection Rate",
                "description": "The current detection rate is below 50%. Consider training the model with more examples of malicious traffic."
            })
        
        # Check if there are many undetected attacks
        if sum(1 for event in security_events if not event["detected"]) > 5:
            report["recommendations"].append({
                "priority": "high",
                "title": "Enhance Security Monitoring",
                "description": "Multiple security events went undetected. Review and update detection rules and models."
            })
        
        # Check top attack types
        top_attack = max(attack_counts.items(), key=lambda x: x[1]) if attack_counts else (None, 0)
        if top_attack[0] and top_attack[1] > 3:
            report["recommendations"].append({
                "priority": "medium",
                "title": f"Address {top_attack[0]} Attacks",
                "description": f"There have been {top_attack[1]} instances of {top_attack[0]} attacks. Consider implementing specific defenses against this type of attack."
            })
        
        # Check for suspicious sources
        suspicious_sources = [src for src, count in traffic_stats.get("by_source", {}).items() 
                             if count > 10 and traffic_stats.get("by_dest", {}).get(src, 0) == 0]
        
        if suspicious_sources:
            report["recommendations"].append({
                "priority": "medium", 
                "title": "Investigate Suspicious Sources",
                "description": f"The following sources are sending large amounts of traffic but not receiving any: {', '.join(suspicious_sources)}"
            })
        
        # Check model performance
        if model_performance and any(model["accuracy"] < 0.8 for model in model_performance.values() if "accuracy" in model):
            report["recommendations"].append({
                "priority": "medium",
                "title": "Improve Model Accuracy",
                "description": "One or more models have accuracy below 80%. Consider retraining with more diverse data or adjusting model parameters."
            })
        
        # Always recommend regular updates
        report["recommendations"].append({
            "priority": "low",
            "title": "Regular Security Updates",
            "description": "Ensure all network devices have the latest security patches and firmware updates."
        })
        
        # Store the report in session state
        st.session_state.network_data["report_data"] = report
        
        # Add report generation to timeline
        st.session_state.network_data["timeline_events"].append({
            "timestamp": report_time,
            "event_type": "report",
            "result": "generated",
            "details": {
                "report_id": report_time.replace(":", "-").replace(" ", "_"),
                "recommendations": len(report["recommendations"])
            }
        })
        
        logger.info(f"Generated security report at {report_time}")
        return report
    except Exception as e:
        logger.error(f"Error generating security report: {str(e)}")
        return None

def export_simulation_state():
    """Export the entire simulation state for saving/resuming"""
    try:
        export_data = {
            "devices": st.session_state.network_data["devices"],
            "connections": st.session_state.network_data["connections"],
            "subnets": st.session_state.network_data["subnets"],
            "acl_rules": st.session_state.network_data["acl_rules"],
            "traffic_log": st.session_state.network_data["traffic_log"][-100:],  # Limit to last 100 entries
            "security_events": st.session_state.network_data["security_events"][-50:],  # Limit to last 50 entries
            "timeline_events": st.session_state.network_data["timeline_events"][-100:],  # Limit to last 100 events
            "training_data": st.session_state.network_data["training_data"],
            "threat_intel": st.session_state.network_data["threat_intel"],
            "display_settings": st.session_state.network_data["display_settings"],
            "version": "1.0",
            "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Convert to JSON
        export_json = json.dumps(export_data, indent=2)
        
        # Create a buffer for the zip file
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
            # Add the JSON data
            zip_file.writestr('simulation_state.json', export_json)
            
            # Try to export the models
            try:
                model_buffer = BytesIO()
                for model_name, model in st.session_state.network_data["models"].items():
                    if model_name != "ensemble" and model is not None:
                        pickle.dump(model, model_buffer)
                
                zip_file.writestr('models.pkl', model_buffer.getvalue())
            except:
                logger.warning("Could not export models")
            
            # Add a CSV export of the traffic log
            csv_buffer = StringIO()
            if st.session_state.network_data["traffic_log"]:
                fieldnames = ["timestamp", "src", "dst", "port", "proto", "size", "result", "reason", "confidence"]
                writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
                writer.writeheader()
                
                for log in st.session_state.network_data["traffic_log"]:
                    row = {field: log.get(field, "") for field in fieldnames}
                    writer.writerow(row)
                
                zip_file.writestr('traffic_log.csv', csv_buffer.getvalue())
            
            # Add a readme file
            readme = f"""Network Security Simulator Export
==============================
Export Time: {export_data['export_time']}
Version: {export_data['version']}

Contents:
- simulation_state.json: Full simulation state
- models.pkl: Trained ML models (if available)
- traffic_log.csv: CSV export of traffic logs

To restore this simulation, use the "Import Simulation" feature.
"""
            zip_file.writestr('README.txt', readme)
        
        # Get the zip data
        zip_data = zip_buffer.getvalue()
        
        logger.info(f"Exported simulation state ({len(zip_data)} bytes)")
        return zip_data
    except Exception as e:
        logger.error(f"Error exporting simulation state: {str(e)}")
        return None

def import_simulation_state(uploaded_file):
    """Import a previously exported simulation state"""
    try:
        # Read the uploaded zip file
        zip_buffer = BytesIO(uploaded_file.read())
        
        with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
            # Extract the JSON data
            if 'simulation_state.json' in zip_file.namelist():
                json_data = zip_file.read('simulation_state.json').decode('utf-8')
                import_data = json.loads(json_data)
                
                # Validate the data
                required_keys = ["devices", "connections", "subnets", "acl_rules", "training_data"]
                if not all(key in import_data for key in required_keys):
                    logger.error("Imported file is missing required data")
                    return False, "Imported file is missing required data"
                
                # Update the session state with the imported data
                st.session_state.network_data["devices"] = import_data["devices"]
                st.session_state.network_data["connections"] = import_data["connections"]
                st.session_state.network_data["subnets"] = import_data["subnets"]
                st.session_state.network_data["acl_rules"] = import_data["acl_rules"]
                st.session_state.network_data["traffic_log"] = import_data.get("traffic_log", [])
                st.session_state.network_data["security_events"] = import_data.get("security_events", [])
                st.session_state.network_data["timeline_events"] = import_data.get("timeline_events", [])
                st.session_state.network_data["training_data"] = import_data["training_data"]
                st.session_state.network_data["threat_intel"] = import_data.get("threat_intel", {})
                st.session_state.network_data["display_settings"] = import_data.get("display_settings", {})
                
                # Try to import models if available
                if 'models.pkl' in zip_file.namelist():
                    try:
                        model_data = zip_file.read('models.pkl')
                        model_buffer = BytesIO(model_data)
                        imported_models = pickle.load(model_buffer)
                        
                        if isinstance(imported_models, dict):
                            st.session_state.network_data["models"] = imported_models
                        else:
                            # Reinitialize models but train them with the imported data
                            initialize_models()
                    except:
                        # If model import fails, reinitialize them
                        initialize_models()
                else:
                    # Reinitialize models
                    initialize_models()
                
                # Add import event to timeline
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                st.session_state.network_data["timeline_events"].append({
                    "timestamp": timestamp,
                    "event_type": "import",
                    "result": "successful",
                    "details": {
                        "original_export_time": import_data.get("export_time", "Unknown"),
                        "version": import_data.get("version", "Unknown")
                    }
                })
                
                logger.info(f"Imported simulation state successfully")
                return True, f"Imported simulation state from {import_data.get('export_time', 'Unknown')}"
            else:
                logger.error("Invalid import file: missing simulation_state.json")
                return False, "Invalid import file: missing simulation_state.json"
    except Exception as e:
        logger.error(f"Error importing simulation state: {str(e)}")
        return False, f"Error importing simulation state: {str(e)}"

def reset_simulation():
    """Reset the simulation to its initial state"""
    try:
        # Store the network configuration temporarily
        network_config = {
            "devices": st.session_state.network_data["devices"].copy(),
            "connections": st.session_state.network_data["connections"].copy(),
            "subnets": st.session_state.network_data["subnets"].copy(),
            "acl_rules": st.session_state.network_data["acl_rules"].copy()
        }
        
        # Reset the session state
        initialize_session_state()
        
        # Restore the network configuration
        st.session_state.network_data["devices"] = network_config["devices"]
        st.session_state.network_data["connections"] = network_config["connections"]
        st.session_state.network_data["subnets"] = network_config["subnets"]
        st.session_state.network_data["acl_rules"] = network_config["acl_rules"]
        
        # Reinitialize models
        initialize_models()
        
        # Add reset event to timeline
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        st.session_state.network_data["timeline_events"].append({
            "timestamp": timestamp,
            "event_type": "reset",
            "result": "successful",
            "details": {
                "network_preserved": True
            }
        })
        
        logger.info("Simulation reset successfully")
        return True
    except Exception as e:
        logger.error(f"Error resetting simulation: {str(e)}")
        return False

# ------------------- SESSION STATE INITIALIZATION -------------------
def initialize_session_state():
    """Initialize or reset the session state"""
    st.session_state.network_data = {
        "devices": {},
        "connections": [],
        "subnets": {},
        "traffic_log": [],
        "security_events": [],
        "last_packet": None,
        "models": {},
        "active_model": "ensemble",
        "training_data": {"X": [], "y": []},
        "acl_rules": [],
        "traffic_stats": {},
        "simulation_state": "idle",
        "timeline_events": [],
        "threat_intel": {},
        "simulation_speed": 1.0,
        "display_settings": {
            "show_animations": True,
            "show_labels": True,
            "dark_mode": False,
            "detail_level": "medium"
        },
        "simulation_id": str(uuid.uuid4()),
        "packet_queue": queue.Queue(),
        "animation_active": False,
        "report_data": {}
    }

if 'first_run' not in st.session_state:
    st.session_state.first_run = True

if st.session_state.first_run or 'network_data' not in st.session_state:
    initialize_session_state()
    # Always initialize with our fixed network configuration
    default_config()
    initialize_models()
    st.session_state.first_run = False

# Always make sure the network devices exist
if not st.session_state.network_data.get("devices"):
    st.warning("Network configuration not found. Initializing default network.")
    default_config()
    initialize_models()

# Add a diagnostic message at the top of the app (can be removed after debugging)
diagnostic_expander = st.sidebar.expander("Diagnostic Information", expanded=False)
with diagnostic_expander:
    st.write(f"Number of devices: {len(st.session_state.network_data.get('devices', {}))}")
    st.write(f"Number of connections: {len(st.session_state.network_data.get('connections', []))}")
    
    # Show network drawing errors if any
    if "network_draw_error" in st.session_state:
        st.error(f"Last network drawing error: {st.session_state.network_draw_error}")
    
    # Add a force reset button
    if st.button("Force Reset Everything"):
        st.session_state.clear()
        st.experimental_rerun()


# ------------------- DEVICE & NETWORK DEFINITIONS -------------------
icons = {
    "pc": "💻", "router": "📡", "switch": "🔀", "cloud": "☁️", "server": "🖥️",
    "firewall": "🔒", "ids": "🔍", "load_balancer": "⚖️", "database": "🗄️",
    "access_point": "📶", "vpn": "🔐", "nas": "💾", "printer": "🖨️"
}

# ------------------- MAIN APPLICATION LAYOUT -------------------

# Title with version and logo
st.title("AI-Powered Network Security Simulator")
st.markdown("### Compare Traditional Security vs. AI-Enhanced Security in a Simulated Network")

# Create tabs for different sections
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    " Network Simulation", 
    " Security Analytics", 
    " ML Models", 
    " Network Config",
    " Timeline & Reports",
    " Manual & Settings"
])

with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("Network Topology")
        
        try:
            # Display the network diagram with error handling
            animation_data = None
            if st.session_state.network_data.get("last_packet") is not None:
                # Get animation data from the last packet
                last_packet = st.session_state.network_data["last_packet"]
                animation_data = {
                    "src": last_packet.get("src"),
                    "dst": last_packet.get("dst"),
                    "result": last_packet.get("result")
                }
            
            # Get path safely
            highlight_path = []
            if st.session_state.network_data.get("last_packet") is not None:
                highlight_path = st.session_state.network_data["last_packet"].get("path", [])
            
            # Draw network with extra safety
            network_fig = draw_network(highlight_path=highlight_path, animation_data=animation_data)
            st.plotly_chart(network_fig, use_container_width=True)
            
            # Clear any previous error
            if "network_draw_error" in st.session_state:
                del st.session_state.network_draw_error
                
        except Exception as e:
            error_msg = f"Error drawing network: {str(e)}"
            st.session_state.network_draw_error = error_msg
            st.error(error_msg)
            
            # Add a fallback display
            st.warning("Displaying text representation of network instead")
            
            # Show simple text representation of the network
            for device, details in st.session_state.network_data.get("devices", {}).items():
                st.write(f"📌 {device} ({details.get('type', 'unknown')}): {details.get('ip', 'no IP')} in {details.get('subnet', 'unknown')} subnet")
        
        # Display recent activity
        with st.expander("Recent Activity Log", expanded=False):
            logs = st.session_state.network_data["traffic_log"][-10:] if st.session_state.network_data["traffic_log"] else []
            
            if logs:
                logs_df = pd.DataFrame([
                    {
                        "Time": log["timestamp"],
                        "Source": log["src"],
                        "Destination": log["dst"],
                        "Port": log["port"],
                        "Protocol": "TCP" if log["proto"] == 6 else "UDP",
                        "Size": f"{log['size']} bytes",
                        "Result": log["result"],
                        "Reason": log.get("reason", "Unknown")
                    }
                    for log in reversed(logs)  # Show newest first
                ])
                
                st.dataframe(logs_df, hide_index=True, use_container_width=True)
            else:
                st.info("No traffic logged yet. Generate some traffic using the simulator.")
    
    with col2:
        st.header("Simulation Controls")
        
        # Initialize models
        initialize_models()
        
        # Control panel
        st.subheader("Packet Simulator")
        
        # Source, destination selection
        devices = st.session_state.network_data["devices"]
        src_devices = [name for name, details in devices.items() if details["type"] in ["pc", "server", "cloud"]]
        dst_devices = [name for name, details in devices.items() if details["type"] in ["server", "database", "cloud"]]
        
        src_device = st.selectbox("Source Device", src_devices, key="sim_src")
        dst_device = st.selectbox("Destination Device", dst_devices, key="sim_dst")
        
        # Protocol details
        col_a, col_b = st.columns(2)
        with col_a:
            port = st.number_input("Port", min_value=1, max_value=65535, value=80, key="sim_port")
            proto = st.selectbox("Protocol", [6, 17], format_func=lambda x: "TCP" if x == 6 else "UDP", key="sim_proto")
        with col_b:
            size = st.slider("Packet Size (bytes)", 50, 8000, 300, key="sim_size")
            priority = st.slider("Priority", 0, 5, 3, key="sim_priority")
        
        # Action buttons
        col_c, col_d = st.columns(2)
        with col_c:
            simulate_packet = st.button("Simulate Single Packet", use_container_width=True)
        with col_d:
            sim_speed = st.select_slider("Simulation Speed", options=[0.5, 1.0, 2.0, 5.0], value=1.0, key="sim_speed")
            st.session_state.network_data["simulation_speed"] = sim_speed
        
        # Continuous simulation and attack simulation
        st.subheader("Advanced Simulation")
        
        col_e, col_f = st.columns(2)
        with col_e:
            simulation_running = st.checkbox("Enable continuous simulation", 
                                           value=st.session_state.network_data["simulation_state"] == "running")
            
            if simulation_running and st.session_state.network_data["simulation_state"] == "idle":
                st.session_state.network_data["simulation_state"] = "running"
            elif not simulation_running and st.session_state.network_data["simulation_state"] == "running":
                st.session_state.network_data["simulation_state"] = "idle"
        
        with col_f:
            attack_options = ["Random Attack", "Port Scan", "DoS", "Data Exfiltration", 
                             "Brute Force", "SQL Injection", "Cross-Site Scripting", "Lateral Movement"]
            attack_type = st.selectbox("Attack Type", attack_options, key="attack_type")
            simulate_attack_btn = st.button("Simulate Attack", use_container_width=True)
        
        # Training feedback
        st.subheader("ML Training")
        st.markdown("Train the AI with the last packet:")
        col_g, col_h = st.columns(2)
        with col_g:
            train_pos = st.button("Train as Allowed", use_container_width=True)
        with col_h:
            train_neg = st.button("Train as Blocked", use_container_width=True)
        
        # Generate synthetic data button
        synth_data = st.button("Generate Synthetic Training Data", use_container_width=True)
        
        # Result Display Area
        st.subheader("Simulation Results")
        result_placeholder = st.empty()

with tab2:
    st.header("Security Analytics Dashboard")
    
    # Update stats
    update_traffic_stats()
    traffic_stats = st.session_state.network_data.get("traffic_stats", {})
    
    # Create metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Traffic", 
                 f"{traffic_stats.get('total_bytes', 0)/1024:.1f} KB", 
                 delta=None)
    with col2:
        st.metric("Allowed Packets", 
                 traffic_stats.get('allowed', 0), 
                 delta=None)
    with col3:
        st.metric("Blocked Packets", 
                 traffic_stats.get('blocked', 0), 
                 delta=None)
    with col4:
        detection_rate = traffic_stats.get('detection_rate', 0)
        st.metric("Detection Rate", 
                 f"{detection_rate:.1%}", 
                 delta=None)
    
    # Create two rows for analytics
    row1_col1, row1_col2 = st.columns(2)
    
    with row1_col1:
        st.subheader("Traffic by Protocol")
        if traffic_stats:
            # Create protocol data
            proto_data = {
                "Protocol": ["TCP", "UDP"],
                "Count": [traffic_stats.get("tcp", 0), traffic_stats.get("udp", 0)]
            }
            
            proto_df = pd.DataFrame(proto_data)
            if not proto_df["Count"].sum() == 0:
                fig = px.bar(proto_df, x="Protocol", y="Count", color="Protocol", 
                            color_discrete_map={"TCP": "#3498db", "UDP": "#2ecc71"})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No protocol data available yet.")
    
    with row1_col2:
        st.subheader("Traffic by Result")
        if traffic_stats:
            # Create result data
            result_data = {
                "Result": ["Allowed", "Blocked"],
                "Count": [traffic_stats.get("allowed", 0), traffic_stats.get("blocked", 0)]
            }
            
            result_df = pd.DataFrame(result_data)
            if not result_df["Count"].sum() == 0:
                fig = px.pie(result_df, names="Result", values="Count", 
                            color="Result", color_discrete_map={"Allowed": "#2ecc71", "Blocked": "#e74c3c"})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No result data available yet.")
    
    row2_col1, row2_col2 = st.columns(2)
    
    with row2_col1:
        st.subheader("Top Traffic Sources")
        if traffic_stats and traffic_stats.get("by_source"):
            # Create source data
            source_items = list(traffic_stats["by_source"].items())
            source_items.sort(key=lambda x: x[1], reverse=True)
            
            source_data = {
                "Source": [item[0] for item in source_items[:5]],
                "Count": [item[1] for item in source_items[:5]]
            }
            
            source_df = pd.DataFrame(source_data)
            if not source_df.empty:
                fig = px.bar(source_df, x="Source", y="Count", color="Count", 
                            color_continuous_scale="Blues")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No source data available yet.")
        else:
            st.info("No source data available yet.")
    
    with row2_col2:
        st.subheader("Top Traffic Destinations")
        if traffic_stats and traffic_stats.get("by_dest"):
            # Create destination data
            dest_items = list(traffic_stats["by_dest"].items())
            dest_items.sort(key=lambda x: x[1], reverse=True)
            
            dest_data = {
                "Destination": [item[0] for item in dest_items[:5]],
                "Count": [item[1] for item in dest_items[:5]]
            }
            
            dest_df = pd.DataFrame(dest_data)
            if not dest_df.empty:
                fig = px.bar(dest_df, x="Destination", y="Count", color="Count", 
                            color_continuous_scale="Oranges")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No destination data available yet.")
        else:
            st.info("No destination data available yet.")
    
    # Add a row for decision analysis
    st.subheader("Decision Analysis")
    row3_col1, row3_col2 = st.columns(2)
    
    with row3_col1:
        st.markdown("#### Decision Sources")
        if traffic_stats and traffic_stats.get("by_reason"):
            # Create reason data
            reason_items = list(traffic_stats["by_reason"].items())
            
            reason_data = {
                "Decision Source": [item[0] for item in reason_items],
                "Count": [item[1] for item in reason_items]
            }
            
            reason_df = pd.DataFrame(reason_data)
            if not reason_df.empty:
                fig = px.pie(reason_df, names="Decision Source", values="Count", 
                            color="Decision Source")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No decision source data available yet.")
        else:
            st.info("No decision source data available yet.")
    
    with row3_col2:
        st.markdown("#### Traffic Over Time")
        if traffic_stats and traffic_stats.get("time_series"):
            # Create time series data
            time_data = traffic_stats["time_series"]
            
            time_df = pd.DataFrame([
                {
                    "Timestamp": item["timestamp"],
                    "Size": item["bytes"],
                    "Result": item["result"]
                }
                for item in time_data
            ])
            
            if not time_df.empty:
                # Group by minute and result
                time_df["Minute"] = time_df["Timestamp"].dt.floor("min")
                grouped = time_df.groupby(["Minute", "Result"])["Size"].sum().reset_index()
                
                fig = px.line(grouped, x="Minute", y="Size", color="Result", 
                             color_discrete_map={"Allowed": "#2ecc71", "Blocked": "#e74c3c"})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No time series data available yet.")
        else:
            st.info("No time series data available yet.")
    
    # Security Events Section
    st.subheader("Security Events")
    
    events = st.session_state.network_data["security_events"]
    if events:
        events_df = pd.DataFrame([
            {
                "Time": event["timestamp"],
                "Type": event["type"],
                "Detected": "✅" if event["detected"] else "❌",
                "Source": event["details"]["src"] if "details" in event and "src" in event["details"] else "-",
                "Destination": event["details"]["dst"] if "details" in event and "dst" in event["details"] else "-",
            }
            for event in reversed(events)  # Show newest first
        ])
        
        st.dataframe(events_df, hide_index=True, use_container_width=True)
    else:
        st.info("No security events detected yet.")

with tab3:
    st.header("AI Security Models")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Model Selection")
        active_model = st.radio(
            "Select Active Model",
            ["sgd", "random_forest", "gradient_boost", "neural_net", "ensemble"],
            index=["sgd", "random_forest", "gradient_boost", "neural_net", "ensemble"].index(
                st.session_state.network_data["active_model"]
            )
        )
        
        st.session_state.network_data["active_model"] = active_model
        
        st.subheader("Model Description")
        model_descriptions = {
            "sgd": "**Stochastic Gradient Descent Classifier**\n\nA linear classifier with SGD training. Fast and efficient for online learning but may be less accurate than ensemble methods. Good for systems with limited resources or where quick updates are needed.",
            "random_forest": "**Random Forest Classifier**\n\nAn ensemble of decision trees. Good balance of accuracy and interpretability with moderate training time. Effective for a wide range of network security problems and resistant to overfitting.",
            "gradient_boost": "**Gradient Boosting Classifier**\n\nA powerful ensemble technique that builds trees sequentially. Often provides the highest accuracy but may take longer to train. Excellent for detecting subtle patterns in network traffic.",
            "neural_net": "**Multi-Layer Perceptron**\n\nA feedforward neural network. Can model complex non-linear relationships but requires more data and may overfit on small datasets. More computationally intensive than other models.",
            "ensemble": "**Meta-Ensemble**\n\nCombines predictions from all other models for the highest accuracy and robustness. Takes advantage of the strengths of each model while mitigating their individual weaknesses."
        }
        
        st.markdown(model_descriptions[active_model])
        
        # Training data summary
        X_train = np.array(st.session_state.network_data["training_data"]["X"])
        y_train = np.array(st.session_state.network_data["training_data"]["y"])
        
        st.subheader("Training Data")
        training_metrics = {
            "Total Examples": len(X_train),
            "Allowed Traffic": sum(y_train == 1),
            "Blocked Traffic": sum(y_train == 0),
            "Allowed %": f"{sum(y_train == 1) / len(y_train) * 100:.1f}%" if len(y_train) > 0 else "0%",
            "Blocked %": f"{sum(y_train == 0) / len(y_train) * 100:.1f}%" if len(y_train) > 0 else "0%"
        }
        
        # Display as a table
        training_df = pd.DataFrame([training_metrics])
        st.dataframe(training_df, hide_index=True, use_container_width=True)
        
        # Show feature importance if possible
        st.subheader("Feature Importance")
        feature_names = ["Source IP", "Dest IP", "Port", "Protocol", "Packet Size", "Hour of Day", "Is Weekend"]
        
        if active_model in ["random_forest", "gradient_boost"]:
            model = st.session_state.network_data["models"][active_model]
            if hasattr(model, "feature_importances_"):
                importances = model.feature_importances_
                
                importance_df = pd.DataFrame({
                    "Feature": feature_names,
                    "Importance": importances
                }).sort_values("Importance", ascending=False)
                
                fig = px.bar(importance_df, x="Feature", y="Importance", color="Importance",
                           color_continuous_scale=["#3498db", "#2ecc71"])
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Feature importance not available for this model yet.")
        else:
            st.info("Feature importance visualization is available for Random Forest and Gradient Boosting models.")
    
    with col2:
        st.subheader("Model Performance")
        
        # Evaluate model performance
        performance = evaluate_model_performance()
        
        if performance:
            # Select model to evaluate
            eval_model = st.selectbox(
                "Select Model to Evaluate",
                list(performance.keys())
            )
            
            # Get metrics for the selected model
            model_perf = performance[eval_model]
            
            # Create metrics for accuracy
            st.metric("Accuracy", f"{model_perf['accuracy']:.2%}")
            
            # Confusion matrix as a heatmap
            st.subheader("Confusion Matrix")
            cm = model_perf["confusion_matrix"]
            
            # Create confusion matrix plot
            cm_data = pd.DataFrame(cm, 
                               columns=["Predicted: Allowed", "Predicted: Blocked"],
                               index=["Actual: Allowed", "Actual: Blocked"])
            
            fig = px.imshow(cm_data, text_auto=True, color_continuous_scale="Blues",
                          x=cm_data.columns, y=cm_data.index,
                          title="Confusion Matrix")
            st.plotly_chart(fig, use_container_width=True)
            
            # Classification metrics table
            st.subheader("Classification Metrics")
            report = model_perf["classification_report"]
            
            metrics_df = pd.DataFrame({
                "Precision": [report["0"]["precision"], report["1"]["precision"], report["macro avg"]["precision"]],
                "Recall": [report["0"]["recall"], report["1"]["recall"], report["macro avg"]["recall"]],
                "F1-Score": [report["0"]["f1-score"], report["1"]["f1-score"], report["macro avg"]["f1-score"]]
            }, index=["Blocked", "Allowed", "Average"])
            
            st.dataframe(metrics_df)
            
            # Precision-Recall curve if available
            if model_perf.get("pr_curve"):
                st.subheader("Precision-Recall Curve")
                pr_data = model_perf["pr_curve"]
                
                pr_df = pd.DataFrame({
                    "Precision": pr_data["precision"],
                    "Recall": pr_data["recall"]
                })
                
                # Create PR curve
                fig = px.line(pr_df, x="Recall", y="Precision", title="Precision-Recall Curve")
                fig.add_shape(
                    type="line", line=dict(dash="dash"),
                    x0=0, x1=1, y0=0.5, y1=0.5  # Base rate line
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Insufficient labeled data to evaluate model performance. Train the model with more examples.")
        
        # Last prediction explanation
        st.subheader("Last Prediction Explanation")
        last_packet = st.session_state.network_data.get("last_packet")
        
        if last_packet and "shap_values" in last_packet and last_packet["shap_values"] is not None:
            st.write(f"Prediction: **{last_packet['result']}** with **{last_packet['confidence']:.2%}** confidence")
            feature_names = ["Source IP", "Dest IP", "Port", "Protocol", "Packet Size", "Hour of Day", "Is Weekend"]
            shap_data = last_packet["shap_values"]
    
            if isinstance(shap_data, dict) and "values" in shap_data:
                shap_values = shap_data["values"]
        
        # Convert to appropriate format if needed
                if isinstance(shap_values, list) and len(shap_values) > 0:
            # For single sample explanation, we might have a list of values
                    if isinstance(shap_values[0], list):
                        shap_values = shap_values[0]
            
            # Convert any nested lists to float values if necessary
                    flattened_shap_values = []
                    for val in shap_values:
                        if isinstance(val, list):
                    # If it's a list with one element, use that element
                            if len(val) == 1:
                                flattened_shap_values.append(float(val[0]))
                    # Otherwise use the mean of the list
                            else:
                                flattened_shap_values.append(float(sum(val) / len(val)))
                        else:
                            flattened_shap_values.append(float(val))
            
            # Create a DataFrame with the flattened values
                    shap_df = pd.DataFrame({
                "Feature": feature_names,
                "Impact": flattened_shap_values
            }).sort_values("Impact", ascending=False)
            
            # Now create the plot with the flattened values
                    fig = px.bar(shap_df, x="Feature", y="Impact", 
                      color="Impact", color_continuous_scale=["#e74c3c", "#3498db"])
            
            # Add a line at zero
                    fig.add_shape(
                type="line", line=dict(dash="dash"),
                x0=-0.5, x1=len(feature_names)-0.5, y0=0, y1=0
            )
            
                    st.plotly_chart(fig, use_container_width=True)
            
            # Add explanation text
                    positive_features = shap_df[shap_df["Impact"] > 0]["Feature"].tolist()
                    negative_features = shap_df[shap_df["Impact"] < 0]["Feature"].tolist()
            
                    if positive_features:
                        st.markdown(f"**Features supporting 'Allow':** {', '.join(positive_features[:3])}")
            
                    if negative_features:
                        st.markdown(f"**Features supporting 'Block':** {', '.join(negative_features[:3])}")
                    else:
                        st.info("SHAP values not in expected format.")
                else:
                    st.info("SHAP values not available for this prediction.")
            else:
                st.info("Make a prediction first to see explanation.")

# Replace the entire Network Config tab section with this simplified version
with tab4:
    st.header("Network Configuration")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Network Topology Management")
        
        # Simple reset button with no configurable network size
        if st.button("Reset to Default Network"):
            default_config()
            st.success(f"Reset to default network configuration")
        
        # Display current network
        st.subheader("Current Network Devices")
        
        devices_df = pd.DataFrame([
            {
                "Device": name,
                "Type": details["type"],
                "IP Address": details["ip"],
                "Subnet": details["subnet"],
                "Status": details.get("status", "normal")
            }
            for name, details in st.session_state.network_data["devices"].items()
        ])
        
        st.dataframe(devices_df, hide_index=True, use_container_width=True)
        
        # Add information about Cisco Packet Tracer implementation
        st.info("This network topology is designed to be replicated in Cisco Packet Tracer for comparison between traditional and AI-enhanced security approaches.")
    
    with col2:
        st.subheader("Access Control Rules")
        
        # Add new ACL rule
        st.markdown("#### Add New Rule")
        
        devices = list(st.session_state.network_data["devices"].keys())
        
        col_a, col_b = st.columns(2)
        with col_a:
            rule_src = st.selectbox("Source", ["Any"] + devices, key="rule_src")
        with col_b:
            rule_dst = st.selectbox("Destination", ["Any"] + devices, key="rule_dst")
        
        col_c, col_d, col_e = st.columns(3)
        with col_c:
            rule_port = st.text_input("Port (comma separated or range)", "Any", help="Examples: '80', '80,443', '1000-2000', 'Any'")
        with col_d:
            rule_proto = st.selectbox("Protocol", ["Any", "TCP", "UDP"], key="rule_proto")
        with col_e:
            rule_action = st.selectbox("Action", ["Allow", "Block"], key="rule_action")
        
        if st.button("Add Rule", use_container_width=True):
            rule = {
                "src": rule_src,
                "dst": rule_dst,
                "port": rule_port,
                "proto": rule_proto,
                "action": rule_action
            }
            
            st.session_state.network_data["acl_rules"].append(rule)
            st.success("Rule added successfully!")
        
        # Display existing rules
        st.markdown("#### Current Rules")
        if st.session_state.network_data["acl_rules"]:
            rules_df = pd.DataFrame([
                {
                    "Source": rule["src"],
                    "Destination": rule["dst"],
                    "Port": rule["port"],
                    "Protocol": rule["proto"],
                    "Action": rule["action"],
                    "Index": i  # Add index for deletion
                }
                for i, rule in enumerate(st.session_state.network_data["acl_rules"])
            ])
            
            # Display rules without the index column
            st.dataframe(rules_df.drop(columns=["Index"]), hide_index=True, use_container_width=True)
            
            # Rule deletion
            rule_to_delete = st.number_input("Rule index to delete", min_value=0, 
                                           max_value=len(st.session_state.network_data["acl_rules"])-1 if st.session_state.network_data["acl_rules"] else 0, 
                                           value=0)
            
            if st.button("Delete Selected Rule"):
                if 0 <= rule_to_delete < len(st.session_state.network_data["acl_rules"]):
                    del st.session_state.network_data["acl_rules"][rule_to_delete]
                    st.success(f"Rule {rule_to_delete} deleted successfully!")
                else:
                    st.error("Invalid rule index")
        else:
            st.info("No ACL rules defined yet.")
        
        # Simplified threat intelligence section
        st.subheader("Threat Intelligence")
        
        with st.expander("View Threat Intelligence Data", expanded=False):
            # Show current blocklist
            st.markdown("#### Current Threat Intelligence")
            
            threat_data = []
            for category, ips in st.session_state.network_data["threat_intel"]["threat_categories"].items():
                for ip in ips:
                    threat_data.append({"IP Address": ip, "Category": category})
            
            if threat_data:
                threat_df = pd.DataFrame(threat_data)
                st.dataframe(threat_df, hide_index=True, use_container_width=True)
            else:
                st.info("No threat intelligence data defined yet.")

with tab5:
    st.header("Timeline & Reports")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Event Timeline")
        
        # Timeline display
        timeline_events = st.session_state.network_data["timeline_events"]
        
        if timeline_events:
            # Convert to DataFrame for display
            timeline_df = pd.DataFrame([
                {
                    "Time": event["timestamp"],
                    "Event Type": event["event_type"].replace("_", " ").title(),
                    "Result": event["result"].replace("_", " ").title(),
                    "Details": str(event.get("details", ""))[:50] + ("..." if len(str(event.get("details", ""))) > 50 else "")
                }
                for event in reversed(timeline_events[-100:])  # Show newest first, limit to 100
            ])
            
            st.dataframe(timeline_df, hide_index=True, use_container_width=True)
            
            # Timeline visualization
            st.subheader("Event Timeline Visualization")
            
            # Group events by type and time (hourly)
            event_types = set(event["event_type"] for event in timeline_events)
            timeline_viz_data = []
            
            # Convert timestamps to datetime
            for event in timeline_events:
                try:
                    timestamp = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                except:
                    try:
                        timestamp = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                    except:
                        continue
                
                # Round to hour
                hour = timestamp.replace(minute=0, second=0, microsecond=0)
                
                timeline_viz_data.append({
                    "Hour": hour,
                    "Event Type": event["event_type"].replace("_", " ").title(),
                    "Count": 1
                })
            
            if timeline_viz_data:
                timeline_viz_df = pd.DataFrame(timeline_viz_data)
                
                # Group by hour and event type
                grouped = timeline_viz_df.groupby(["Hour", "Event Type"])["Count"].sum().reset_index()
                
                # Create timeline visualization
                fig = px.line(grouped, x="Hour", y="Count", color="Event Type", 
                             title="Events Over Time")
                
                # Improve layout
                fig.update_layout(xaxis_title="Time", yaxis_title="Number of Events")
                
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timeline events recorded yet.")
    
    with col2:
        st.subheader("Security Reports")
        
        # Generate report button
        if st.button("Generate Security Report", use_container_width=True):
            with st.spinner("Generating comprehensive security report..."):
                report = generate_security_report()
                
                if report:
                    st.success("Security report generated successfully!")
                else:
                    st.error("Error generating security report.")
        
        # Display report if available
        report_data = st.session_state.network_data.get("report_data")
        
        if report_data:
            with st.expander("Report Summary", expanded=True):
                # Create summary metrics
                summary = report_data["summary"]
                
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("Detection Rate", f"{summary['detection_rate']:.1%}")
                with col_b:
                    st.metric("Security Events", summary["security_events"])
                with col_c:
                    st.metric("Total Traffic", f"{summary['total_traffic_volume']/1024:.1f} KB")
                
                # Show top attack types
                if summary.get("attack_types"):
                    st.subheader("Attack Type Distribution")
                    
                    attack_df = pd.DataFrame({
                        "Attack Type": list(summary["attack_types"].keys()),
                        "Count": list(summary["attack_types"].values())
                    })
                    
                    fig = px.pie(attack_df, names="Attack Type", values="Count", title="Attack Distribution")
                    st.plotly_chart(fig, use_container_width=True)
            
            with st.expander("Recommendations", expanded=True):
                recommendations = report_data.get("recommendations", [])
                
                if recommendations:
                    for i, rec in enumerate(recommendations):
                        priority_color = {
                            "high": "🔴",
                            "medium": "🟠",
                            "low": "🟢"
                        }.get(rec["priority"], "⚪")
                        
                        st.markdown(f"#### {priority_color} {rec['title']}")
                        st.markdown(rec["description"])
                        
                        if i < len(recommendations) - 1:
                            st.markdown("---")
                else:
                    st.info("No recommendations generated.")
            
            with st.expander("Technical Details", expanded=False):
                st.markdown("#### Model Performance")
                
                model_performance = report_data.get("model_performance")
                if model_performance:
                    # Show accuracy for each model
                    model_acc = {}
                    for model_name, metrics in model_performance.items():
                        if "accuracy" in metrics:
                            model_acc[model_name] = metrics["accuracy"]
                    
                    if model_acc:
                        model_df = pd.DataFrame({
                            "Model": list(model_acc.keys()),
                            "Accuracy": list(model_acc.values())
                        })
                        
                        fig = px.bar(model_df, x="Model", y="Accuracy", title="Model Accuracy Comparison")
                        st.plotly_chart(fig, use_container_width=True)
                
                # Download report as JSON
                report_json = json.dumps(report_data, indent=2, default=datetime_converter)
                b64 = base64.b64encode(report_json.encode()).decode()
                href = f'<a href="data:application/json;base64,{b64}" download="security_report_{report_data["timestamp"].replace(":", "-").replace(" ", "_")}.json">Download Report as JSON</a>'
                st.markdown(href, unsafe_allow_html=True)
                
                # Generate PDF report (placeholder - would need a PDF generation library)
                st.markdown("#### Export as PDF")
                st.info("This feature would generate a professionally formatted PDF report.")
        else:
            st.info("No security report generated yet. Click 'Generate Security Report' to create one.")
        
        # Simulation state management
        st.subheader("Simulation State Management")
        
        col_d, col_e = st.columns(2)
        with col_d:
            if st.button("Export Simulation State", use_container_width=True):
                with st.spinner("Exporting simulation state..."):
                    export_data = export_simulation_state()
                    
                    if export_data:
                        b64 = base64.b64encode(export_data).decode()
                        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                        href = f'<a href="data:application/zip;base64,{b64}" download="network_simulation_{date_str}.zip">Download Simulation State</a>'
                        st.markdown(href, unsafe_allow_html=True)
                        st.success("Simulation state exported successfully!")
                    else:
                        st.error("Error exporting simulation state.")
        
        with col_e:
            uploaded_state = st.file_uploader("Import Simulation State", type=["zip"])
            
            if uploaded_state is not None:
                if st.button("Load Imported State", use_container_width=True):
                    with st.spinner("Loading simulation state..."):
                        success, message = import_simulation_state(uploaded_state)
                        
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
        
        # Reset button
        if st.button("Reset Simulation", use_container_width=True):
            if reset_simulation():
                st.success("Simulation reset successfully!")
            else:
                st.error("Error resetting simulation.")

with tab6:
    st.header("User Manual & Settings")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # User manual content
        st.subheader("User Manual")
        
        # Create tabs for different manual sections
        manual_tab1, manual_tab2, manual_tab3, manual_tab4 = st.tabs([
            "Introduction & Overview", 
            "Features & Usage", 
            "AI Integration", 
            "Comparison with Traditional"
        ])
        
        with manual_tab1:
            st.markdown("""
            # AI-Powered Network Security Simulator
            
            ## Introduction
            
            Welcome to the AI-Powered Network Security Simulator! This advanced application allows you to:
            
            1. Simulate realistic network environments with various devices and subnets
            2. Compare traditional network security (ACLs, firewalls) with AI-enhanced security
            3. Visualize traffic flows and security events in real-time
            4. Train and evaluate machine learning models for network security
            
            ## Why This Tool?
            
            Traditional network security relies on static rules and signatures that cannot adapt to new threats.
            AI-powered security can learn from patterns and detect anomalies that would bypass traditional
            security measures. This simulator demonstrates the differences between these approaches and
            highlights the advantages of AI integration.
            
            ## Overview of Tabs
            
            - **Network Simulation**: View and interact with the network topology, simulate traffic and attacks
            - **Security Analytics**: Analyze traffic patterns, view security events, and visualize statistics
            - **ML Models**: Train and evaluate machine learning models for traffic classification
            - **Network Config**: Configure network devices, connections, and access control rules
            - **Timeline & Reports**: View chronological events and generate security reports
            - **Manual & Settings**: Access user manual and adjust application settings
            """)
        
        with manual_tab2:
            st.markdown("""
            # Features & Usage Guide
            
            ## Network Simulation Tab
            
            ### Network Topology
            - The network diagram shows all devices, connections, and subnets
            - Devices are color-coded by subnet
            - Compromised devices have red borders
            - Hover over devices to see details
            
            ### Packet Simulator
            - Select source and destination devices
            - Configure port, protocol, and packet size
            - Click "Simulate Packet" to send a single packet
            - The system will determine if the packet should be allowed or blocked
            
            ### Advanced Simulation
            - Toggle "Enable continuous simulation" for ongoing traffic
            - Select an attack type and click "Simulate Attack"
            - The simulator will generate realistic attack traffic
            
            ### ML Training
            - After simulating traffic, use "Train as Allowed" or "Train as Blocked"
            - This teaches the AI model how to classify similar traffic in the future
            - "Generate Synthetic Training Data" creates varied examples automatically
            
            ## Security Analytics Tab
            
            - View traffic statistics and security events
            - Analyze traffic by protocol, result, source, and destination
            - Examine decision sources (ML, ACL, Threat Intel)
            - Review security events with timestamps and details
            
            ## ML Models Tab
            
            - Select different machine learning models
            - View model descriptions and training data statistics
            - Examine feature importance for interpretable models
            - Evaluate model performance with accuracy metrics and confusion matrices
            - View SHAP explanations for individual predictions
            
            ## Network Config Tab
            
            - Reset to different network sizes (small, medium, large)
            - View and manage network devices
            - Import/export network configurations
            - Configure access control rules
            - Manage threat intelligence data
            
            ## Timeline & Reports Tab
            
            - View chronological events with details
            - Generate comprehensive security reports
            - Export simulation state for later resumption
            - Reset the simulation while preserving network configuration
            """)
        
        with manual_tab3:
            st.markdown("""
            # AI Integration
            
            ## How AI Enhances Network Security
            
            Traditional network security relies on predefined rules and signatures. While effective against known threats, 
            this approach struggles with:
            
            1. Zero-day exploits
            2. Novel attack patterns
            3. Insider threats
            4. Sophisticated evasion techniques
            
            The AI components in this simulator address these limitations by:
            
            ### 1. Anomaly Detection
            
            Machine learning models learn "normal" traffic patterns and can identify anomalies that may indicate attacks,
            even if they don't match known signatures.
            
            ### 2. Behavioral Analysis
            
            AI models analyze behavior patterns over time, detecting subtle changes that may indicate a compromise
            or malicious activity.
            
            ### 3. Adaptive Security
            
            As new threats emerge, the AI models can be trained to recognize them, improving detection rates
            without manual rule updates.
            
            ### 4. Decision Explanation
            
            SHAP (SHapley Additive exPlanations) values help security analysts understand why the AI made
            particular decisions, building trust in automated systems.
            
            ## AI Models in the Simulator
            
            The simulator implements several machine learning models:
            
            - **SGD Classifier**: A linear model suitable for online learning
            - **Random Forest**: An ensemble of decision trees that excels at capturing complex patterns
            - **Gradient Boosting**: A powerful sequential ensemble technique
            - **Neural Network**: A multilayer perceptron for modeling complex non-linear relationships
            - **Meta-Ensemble**: Combines predictions from all models for highest accuracy
            
            ## How to Use AI Effectively
            
            1. **Training the models**: Use the "Train as Allowed" and "Train as Blocked" buttons to teach the system
            2. **Generating synthetic data**: Create varied training examples with the synthetic data generator
            3. **Evaluating performance**: Compare models using accuracy metrics and confusion matrices
            4. **Understanding decisions**: Examine SHAP values to understand prediction factors
            5. **Combining with traditional security**: Use AI alongside ACLs and threat intelligence for defense in depth
            """)
        
        with manual_tab4:
            st.markdown("""
            # Comparing Traditional vs. AI-Enhanced Security
            
            ## Traditional Security Approaches
            
            ### Access Control Lists (ACLs)
            
            ACLs define static rules for allowing or blocking traffic based on:
            - Source and destination addresses
            - Ports and protocols
            - Traffic direction
            
            **Strengths**:
            - Deterministic behavior
            - Low computational overhead
            - Easy to audit
            
            **Limitations**:
            - Cannot detect unknown threats
            - Rule maintenance becomes complex
            - No ability to learn or adapt
            
            ### Packet Filtering Firewalls
            
            Basic firewalls inspect packet headers and apply rules similar to ACLs.
            
            **Strengths**:
            - Reliable for known threat patterns
            - Well-established technology
            - Relatively simple implementation in Packet Tracer
            
            **Limitations**:
            - Cannot inspect packet content deeply
            - No behavior analysis capability
            - Rules must be manually updated
            
            ## AI-Enhanced Security
            
            ### Machine Learning Classification
            
            ML models analyze traffic patterns to classify legitimate vs. malicious traffic.
            
            **Strengths**:
            - Can detect unknown threats
            - Adapts to changing network conditions
            - Reduces false positives over time
            
            **Limitations**:
            - Requires training data
            - More computational resources
            - May be challenging to implement in Packet Tracer
            
            ### Anomaly Detection
            
            AI identifies deviations from normal behavior patterns.
            
            **Strengths**:
            - Detects subtle attack indicators
            - Works without prior knowledge of threats
            - Continuously improves with new data
            
            **Limitations**:
            - Initial false positives until trained
            - More complex to deploy and manage
            
            ## Implementation in Cisco Packet Tracer
            
            When replicating this security simulator in Packet Tracer:
            
            1. **Traditional security** can be implemented using:
               - Router ACLs
               - Firewall rules
               - VLAN segmentation
               - IDS/IPS devices
            
            2. **AI capabilities** would be simulated through:
               - Predefined scenarios showing what AI would detect
               - Manual updates to simulate learning
               - Side-by-side comparison with this simulator
            
            ## Key Metrics for Comparison
            
            When comparing traditional vs. AI approaches, consider:
            
            - **Detection Rate**: Percentage of attacks successfully identified
            - **False Positive Rate**: Legitimate traffic incorrectly blocked
            - **Adaptability**: Ability to detect new attack types
            - **Resource Requirements**: Processing and memory needs
            - **Ease of Management**: Effort required for maintenance
            """)
    
    with col2:
        # Display settings
        st.subheader("Display Settings")
        
        # If display_settings doesn't exist in the session state, create it with defaults
        if "display_settings" not in st.session_state.network_data:
            st.session_state.network_data["display_settings"] = {
                "show_animations": True,
                "show_labels": True,
                "dark_mode": False,
                "detail_level": "medium"
            }
        
        settings = st.session_state.network_data["display_settings"]
        
        # Create toggles for different settings
        show_animations = st.toggle("Show Animations", value=settings.get("show_animations", True))
        show_labels = st.toggle("Show Labels", value=settings.get("show_labels", True))
        dark_mode = st.toggle("Dark Mode", value=settings.get("dark_mode", False))
        detail_level = st.select_slider("Detail Level", 
                                      options=["low", "medium", "high"], 
                                      value=settings.get("detail_level", "medium"))
        
        # Update settings if changed
        if (show_animations != settings.get("show_animations") or
            show_labels != settings.get("show_labels") or
            dark_mode != settings.get("dark_mode") or
            detail_level != settings.get("detail_level")):
            
            settings["show_animations"] = show_animations
            settings["show_labels"] = show_labels
            settings["dark_mode"] = dark_mode
            settings["detail_level"] = detail_level
            
            st.success("Display settings updated!")
        
        # About section
        st.subheader("About")
        st.markdown("""
        **AI-Powered Network Security Simulator**
        
        Version 1.0
        
        This application demonstrates the integration of artificial intelligence 
        with traditional network security approaches. It provides a realistic 
        simulation environment for educational purposes and security testing.
        
        The simulator is designed to be implemented alongside Cisco Packet Tracer 
        for comparing traditional vs. AI-enhanced security approaches.
        
        © 2025 Network Security Solutions
        """)
        
        # Statistics
        st.subheader("Simulator Statistics")
        
        # Calculate statistics
        num_devices = len(st.session_state.network_data["devices"])
        num_connections = len(st.session_state.network_data["connections"])
        num_subnets = len(st.session_state.network_data["subnets"])
        num_traffic_logs = len(st.session_state.network_data["traffic_log"])
        num_security_events = len(st.session_state.network_data["security_events"])
        num_timeline_events = len(st.session_state.network_data["timeline_events"])
        
        # Display as metrics
        st.metric("Devices", num_devices)
        st.metric("Connections", num_connections)
        st.metric("Subnets", num_subnets)
        st.metric("Traffic Logs", num_traffic_logs)
        st.metric("Security Events", num_security_events)
        st.metric("Timeline Events", num_timeline_events)

# ------------------- HANDLE SIMULATION -------------------

# Handle single packet simulation
if simulate_packet:
    with st.spinner("Simulating packet..."):
        result, confidence, details = make_prediction(src_device, dst_device, port, proto, size)
        
        # Show result with detailed explanation
        result_color = "green" if result == "Allowed" else "red"
        
        result_html = f"""
        <div style="padding: 10px; border-radius: 5px; background-color: {'rgba(0, 200, 0, 0.1)' if result == 'Allowed' else 'rgba(200, 0, 0, 0.1)'}; margin-bottom: 10px;">
            <h3 style="color: {result_color};">Packet {result}</h3>
            <p><strong>Confidence:</strong> {confidence:.2%}</p>
            <p><strong>Decision made by:</strong> {details.get('reason', 'Unknown')}</p>
        </div>
        """
        
        result_placeholder.markdown(result_html, unsafe_allow_html=True)
        
        # Show additional details with expandable sections
        with result_placeholder.expander("Path Details", expanded=False):
            if details.get("path"):
                path_devices = []
                for src, dst in details["path"]:
                    if src not in path_devices:
                        path_devices.append(src)
                    if dst not in path_devices:
                        path_devices.append(dst)
                
                path_str = " → ".join(path_devices)
                st.markdown(f"**Path:** {path_str}")
            else:
                st.markdown("No path information available (packet was blocked)")
        
        with result_placeholder.expander("Detailed Analysis", expanded=False):
            # Create detailed analysis of the decision
            st.markdown("#### Decision Factors")
            
            factors_df = pd.DataFrame([
                {"Factor": "ACL Rule", "Result": "Allowed" if details.get("acl_result") else "Blocked", 
                 "Confidence": "100%", "Impact": "High"},
                {"Factor": "Threat Intelligence", "Result": "Detected" if details.get("threat_check", {}).get("detected") else "Not Detected", 
                 "Confidence": f"{details.get('threat_check', {}).get('confidence', 0):.0%}" if details.get("threat_check", {}).get("detected") else "N/A", 
                 "Impact": "High" if details.get("threat_check", {}).get("detected") else "Low"},
                {"Factor": "ML Model", "Result": "Allowed" if details.get("ml_prediction") == 1 else "Blocked", 
                 "Confidence": f"{confidence:.0%}", "Impact": "Medium"}
            ])
            
            st.dataframe(factors_df, hide_index=True, use_container_width=True)
            
            if details.get("threat_check", {}).get("detected"):
                st.markdown(f"**Threat detected:** {details['threat_check']['type']}")
                st.markdown(f"**Details:** {details['threat_check']['details']}")

# Handle attack simulation
if simulate_attack_btn:
    with st.spinner(f"Simulating {attack_type} attack..."):
        if attack_type == "Random Attack":
            attack_name, attack_results = simulate_attack()
        else:
            attack_name, attack_results = simulate_attack(attack_type)
        
        # Display results
        detected = sum(1 for r in attack_results if r["detected"])
        total = len(attack_results)
        detection_rate = detected / total if total > 0 else 0
        
        # Create a visual result
        result_html = f"""
        <div style="padding: 10px; border-radius: 5px; background-color: {'rgba(0, 200, 0, 0.1)' if detection_rate > 0.5 else 'rgba(200, 0, 0, 0.1)'}; margin-bottom: 10px;">
            <h3>Attack Simulation Results</h3>
            <p><strong>Attack Type:</strong> {attack_name}</p>
            <p><strong>Detection Rate:</strong> {detected}/{total} packets ({detection_rate:.1%})</p>
            <p><strong>Status:</strong> {'Attack mostly detected' if detection_rate > 0.5 else 'Attack mostly missed'}</p>
        </div>
        """
        
        result_placeholder.markdown(result_html, unsafe_allow_html=True)
        
        # Show detailed results in an expander
        with result_placeholder.expander("Detailed Attack Results", expanded=True):
            # Create a DataFrame of the results
            results_df = pd.DataFrame([
                {
                    "Packet": i+1,
                    "Source": r["packet"]["src"],
                    "Destination": r["packet"]["dst"],
                    "Port": r["packet"]["port"],
                    "Protocol": "TCP" if r["packet"]["proto"] == 6 else "UDP",
                    "Size": f"{r['packet']['size']} bytes",
                    "Detected": "✅" if r["detected"] else "❌",
                    "Confidence": f"{r['confidence']:.1%}",
                    "Decision By": r["packet"].get("reason", "Unknown")
                }
                for i, r in enumerate(attack_results)
            ])
            
            st.dataframe(results_df, hide_index=True, use_container_width=True)
            
            # Show a visual summary
            st.subheader("Detection by Decision Source")
            
            # Count detections by decision source
            detection_counts = {}
            for r in attack_results:
                if r["detected"]:
                    reason = r["packet"].get("reason", "Unknown")
                    detection_counts[reason] = detection_counts.get(reason, 0) + 1
            
            if detection_counts:
                detection_df = pd.DataFrame({
                    "Decision Source": detection_counts.keys(),
                    "Detections": detection_counts.values()
                })
                
                fig = px.pie(detection_df, names="Decision Source", values="Detections", 
                           title="Attack Packets Detected By")
                st.plotly_chart(fig, use_container_width=True)

# Handle training actions
if train_pos:
    if train_model(1):
        st.success("✅ Model trained with positive example (Allowed)!")
elif train_neg:
    if train_model(0):
        st.success("✅ Model trained with negative example (Blocked)!")

# Handle synthetic data generation
if synth_data:
    with st.spinner("Generating synthetic training data..."):
        num_generated = generate_synthetic_training_data(50)
        if num_generated > 0:
            st.success(f"✅ Generated {num_generated} synthetic training examples!")
        else:
            st.error("Could not generate synthetic data. Please create some initial examples first.")

# Handle continuous simulation if enabled
if st.session_state.network_data["simulation_state"] == "running":
    # Get simulation speed
    sim_speed = st.session_state.network_data.get("simulation_speed", 1.0)
    
    # Create a placeholder for realtime updates
    realtime_placeholder = st.empty()
    
    # Simulate traffic with adjusted probability based on speed
    if random.random() < 0.15 * sim_speed:  # Adjust attack probability based on speed
        # Simulate attack (less frequently)
        attack_name, attack_results = simulate_attack()
        detected = sum(1 for r in attack_results if r["detected"])
        total = len(attack_results)
        
        with realtime_placeholder.container():
            alert_type = "warning" if detected/total > 0.5 else "error"
            if alert_type == "warning":
                st.warning(f"Attack detected: {attack_name} ({detected}/{total} packets blocked)")
            else:
                st.error(f"Attack partially detected: {attack_name} (only {detected}/{total} packets blocked)")
    else:
        # Simulate normal traffic (more frequently)
        normal_results = simulate_normal_traffic()
        
        if normal_results:
            allowed = sum(1 for r in normal_results if r["result"] == "Allowed")
            total = len(normal_results)
            
            with realtime_placeholder.container():
                if allowed == total:
                    st.info(f"Normal traffic: {allowed}/{total} flows allowed")
                else:
                    st.warning(f"Normal traffic: {allowed}/{total} flows allowed, {total-allowed} blocked")
    
    # Update the traffic stats
    update_traffic_stats()
    
    # Add slight delay adjusted by simulation speed
    time.sleep(1.0 / sim_speed)

# ------------------- STARTUP INITIALIZATION -------------------

# Run on first load
if st.session_state.first_run:
    # Initialize with default medium network
    default_config("medium")
    initialize_models()
    
    # Clear the first run flag
    st.session_state.first_run = False