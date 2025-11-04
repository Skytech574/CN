
import sqlite3
from datetime import datetime
import time
import random
import sys


def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect('quiz.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_traffic_db():
    """Ensure database and traffic_stats table exist"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        
        c.execute('''CREATE TABLE IF NOT EXISTS traffic_stats
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      packet_type TEXT NOT NULL,
                      count INTEGER DEFAULT 1,
                      timestamp TEXT NOT NULL)''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"✗ Database error: {e}")
        return False

def simulate_traffic():
    """Generate simulated network traffic data"""
    packet_types = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "ARP"]
    
    print("\n" + "="*70)
    print("📊 NETWORK TRAFFIC SIMULATOR")
    print("="*70)
    
   
    if not init_traffic_db():
        print("✗ Failed to initialize database")
        return
    
    packet_count = 0
    
    try:
        while True:
            try:
                conn = get_db_connection()
                c = conn.cursor()
                
                
                packet_type = random.choice(packet_types)
                
               
                count = random.randint(1, 5)
                
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""INSERT INTO traffic_stats (packet_type, count, timestamp) 
                            VALUES (?, ?, ?)""",
                          (packet_type, count, timestamp))
                
                conn.commit()
                conn.close()
                
                packet_count += 1
                time_display = datetime.now().strftime('%H:%M:%S')
                print(f"[{time_display}] Captured {count:2d} × {packet_type:5s} packets (Total: {packet_count:4d})")
                
               
                delay = random.uniform(0.5, 3.0)
                time.sleep(delay)
            
            except sqlite3.Error as db_err:
                print(f"✗ Database error: {db_err}")
                time.sleep(2)
            except Exception as err:
                print(f"✗ Error: {err}")
                time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print(" Traffic simulator stopped")
        print(f" Total packets simulated: {packet_count}")
        print(" Data saved to database and visible on dashboard")
        print("="*70 + "\n")
        sys.exit(0)



def real_packet_capture():
   
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        
        print("\n" + "="*70)
        print("REAL PACKET SNIFFER (requires Npcap/libpcap)")
        print("="*70)
        print("WARNING: Run this with admin/sudo privileges!")
        print("Press Ctrl+C to stop")
        print("="*70 + "\n")
        
        if not init_traffic_db():
            print("✗ Failed to initialize database")
            return
        
        packet_count = 0
        
        def packet_callback(packet):
            
            nonlocal packet_count
            
            try:
                conn = get_db_connection()
                c = conn.cursor()
                
                packet_type = "OTHER"
                
                if packet.haslayer(TCP):
                    packet_type = "TCP"
                elif packet.haslayer(UDP):
                    packet_type = "UDP"
                elif packet.haslayer(ICMP):
                    packet_type = "ICMP"
                elif packet.haslayer(IP):
                    packet_type = "IP"
                
               
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""INSERT INTO traffic_stats (packet_type, count, timestamp) 
                            VALUES (?, 1, ?)""",
                          (packet_type, timestamp))
                
                conn.commit()
                conn.close()
                
                packet_count += 1
                time_display = datetime.now().strftime('%H:%M:%S')
                print(f"[{time_display}] Captured {packet_type:5s} packet (Total: {packet_count})")
            
            except Exception as e:
                print(f"✗ Error processing packet: {e}")
        
        
        print("Starting real packet capture...")
        print("This will capture actual network traffic on your interface\n")
        sniff(prn=packet_callback, store=0, count=0)
    
    except ImportError:
        print("\n Scapy not installed")
        
        simulate_traffic()
    
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print(" Real packet sniffer stopped")
        print(" Data saved to database")
        print("="*70 + "\n")
        sys.exit(0)
    except PermissionError:
        print("\n Permission denied!")
        
        simulate_traffic()
    except Exception as e:
        print(f"\n Error during packet capture: {e}")
       
        simulate_traffic()



if __name__ == "__main__":
    print("\n" + "="*70)
    print(" SMART EVENT LAN - NETWORK TRAFFIC MONITOR")
    print("="*70)
    
    
    if len(sys.argv) > 1 and sys.argv[1] == '--real':
        print("Mode: REAL PACKET CAPTURE")
        print("(requires Npcap on Windows)")
        print("="*70)
        real_packet_capture()
    else:
        print("Mode: SIMULATED TRAFFIC SIMULATOR ✅")
        print("(No admin privileges needed - RECOMMENDED)")
        print("\nTo use real packet capture, run:")
        print("  python sniffer.py --real")
        print("="*70)
        simulate_traffic()
