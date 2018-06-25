import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import java.util.ArrayList;
import java.util.List;
import java.util.GregorianCalendar;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IPScanner extends Thread {
	
	private double pgindex = 0.0; 
	private double indextmp = 0.0; 
	String titles[] = new String[] { "IP", "Ping", "TTL", "Hostname", "Ports[+0]" };
	Object[][] stats = getNetworkStats();
	
	public IPScanner() throws UnknownHostException{
		
		JFrame jframe = new JFrame();
		jframe.setTitle("IP Scanner");
		jframe.setBackground(SystemColor.activeCaption);
				
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		
		JPanel con = new JPanel();
		con.setLayout(new BorderLayout());
		
		JPanel status = new JPanel();
		status.setMinimumSize(new Dimension(0, 0));
		
		JTable table = new JTable(stats, titles);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		table.setColumnSelectionAllowed(true);
		
		JScrollPane scroll = new JScrollPane(table);
		panel.add(scroll, BorderLayout.CENTER);
		jframe.setBounds(400, 200, 550, 400);
		
		jframe.getContentPane().add(panel, BorderLayout.CENTER);
		jframe.getContentPane().add(con, BorderLayout.NORTH);
		
		jframe.getContentPane().add(status, BorderLayout.SOUTH);
		status.setLayout(new GridLayout(0, 4, 0, 0));
		
		JLabel lblReady = new JLabel("Ready");
		lblReady.setAlignmentX(Component.CENTER_ALIGNMENT);
		lblReady.setHorizontalTextPosition(SwingConstants.LEADING);
		lblReady.setDisplayedMnemonic(KeyEvent.VK_ENTER);
		lblReady.setBorder(new BevelBorder(BevelBorder.LOWERED));
		status.add(lblReady);
		
		JLabel display = new JLabel("Display: ALL");
		display.setBorder(new BevelBorder(BevelBorder.LOWERED));
		display.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		status.add(display);
		
		JLabel lblThreads = new JLabel("Threads: ");
		lblThreads.setBorder(new BevelBorder(BevelBorder.LOWERED));
		status.add(lblThreads);
		
		JProgressBar progressBar = new JProgressBar();
		progressBar.setStringPainted(true);
		progressBar.setBackground(Color.LIGHT_GRAY);
		status.add(progressBar);
		
		JToolBar toolbar1 = new JToolBar();
		toolbar1.setBackground(UIManager.getColor("MenuBar.background"));
		toolbar1.setFloatable(false);
		con.add(toolbar1, BorderLayout.NORTH);		
			
		JLabel lblIpRange = new JLabel("   IP Range: ");
		lblIpRange.setHorizontalAlignment(SwingConstants.LEFT);
		lblIpRange.setFont(new Font("Microsoft Tai Le", Font.PLAIN, 12));
		toolbar1.add(lblIpRange);
		
		InetAddress myip = InetAddress.getLocalHost();
		String fixedip = myip.getHostAddress().substring(0, myip.getHostAddress().lastIndexOf(".") + 1);
		
		JTextField textField1 = new JTextField();
		textField1.setText(fixedip + "1");
		textField1.setHorizontalAlignment(SwingConstants.LEFT);
		toolbar1.add(textField1);
		textField1.setColumns(10);
		
		JLabel lblTo = new JLabel(" to ");
		lblTo.setHorizontalAlignment(SwingConstants.LEFT);
		lblTo.setFont(new Font("Microsoft Tai Le", Font.PLAIN, 12));
		toolbar1.add(lblTo);
		
		JTextField textField2 = new JTextField();
		textField2.setText(fixedip + "254");
		textField2.setHorizontalAlignment(SwingConstants.LEFT);
		toolbar1.add(textField2);
		textField2.setColumns(10);
		
		JLabel label = new JLabel("   ");
		toolbar1.add(label);
		
		JComboBox comboBox1 = new JComboBox();
		comboBox1.setModel(new DefaultComboBoxModel(new String[] {"IP Range", "Random", "Text File"}));
		comboBox1.setToolTipText("");
		toolbar1.add(comboBox1);
		
		JLabel label_1 = new JLabel("  ");
		toolbar1.add(label_1);
		
		JButton button = new JButton("");
		button.setSelectedIcon(null);
		button.setIcon(new ImageIcon("settings.png"));
		toolbar1.add(button);
		
		JLabel label_6 = new JLabel("  ");
		toolbar1.add(label_6);
		
		JToolBar toolbar2 = new JToolBar();
		toolbar2.setBackground(UIManager.getColor("MenuBar.background"));
		toolbar2.setFloatable(false);
		con.add(toolbar2, BorderLayout.SOUTH);	
		
		JLabel lblHostname = new JLabel("Hostname: ");
		lblHostname.setFont(new Font("Microsoft Tai Le", Font.PLAIN, 12));
		toolbar2.add(lblHostname);
		
		JTextField textField3 = new JTextField(10);
		textField3.setText(myip.getHostName());
		toolbar2.add(textField3);
		
		JLabel label_2 = new JLabel("  ");
		toolbar2.add(label_2);
		long finish = 0;
		
		JButton ipUp = new JButton();
		ipUp.setIcon(new ImageIcon("up.png"));
		ipUp.setHorizontalAlignment(SwingConstants.LEADING);
		ipUp.setFont(new Font("Microsoft Tai Le", Font.PLAIN, 12));
		ipUp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		
		ipUp.setText(" IP");
		toolbar2.add(ipUp);
		ipUp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		
		JLabel label_3 = new JLabel("  ");
		toolbar2.add(label_3);
		
		JComboBox comboBox2 = new JComboBox();
		comboBox2.setForeground(Color.BLACK);
		comboBox2.setBackground(Color.WHITE);
		comboBox2.setModel(new DefaultComboBoxModel(new String[] {"/26", "/24", "/16", "255...192", "255...128", "255...0", "255..0.0", "255.0.0.0"}));
		toolbar2.add(comboBox2);
		
		JLabel label_4 = new JLabel("  ");
		toolbar2.add(label_4);
		
		JButton start = new JButton();
		start.setBackground(UIManager.getColor("Button.background"));
		start.setHorizontalAlignment(SwingConstants.LEADING);
		start.setIcon(new ImageIcon("start.png"));
		start.setFont(new Font("Microsoft Tai Le", Font.PLAIN, 12));
		start.setText("  Start");
		toolbar2.add(start);
		
		start.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
			
				
				new Thread(() -> {
					
					start.setText("  Stop!");
					start.setIcon(new ImageIcon("stop.png"));
					
					Pinging[] pg = new Pinging[254];
	
					for (int i = 0; i < 254; i++) {
						pg[i] = new Pinging(fixedip + (i + 1));
						pg[i].start();
					}
					
					for (int i = 0; i < 254; i++) {
						
						Object[] msg = pg[i].getMsg();
						
						if (msg[1] != null | msg[2] != null | msg[3] != null) {
							stats[i][0] = "¡Ü" + msg[0];
							table.repaint();
						} else {
							stats[i][0] = "¡Û" + msg[0];
							table.repaint();
						}
						
						if (msg[1] != null) {
							stats[i][1] = msg[1];
							table.repaint();
						} else {
							stats[i][1] = "[n/a]";
							table.repaint();
						}
						if (msg[2] != null) {
							stats[i][2] = msg[2];
							table.repaint();
						} else {
							stats[i][2] = "[n/s]";
							table.repaint();
						}
						if (msg[3] != null) {
							stats[i][3] = msg[3];
							table.repaint();
						} else {
							stats[i][3] = "[n/s]";
							table.repaint();
						}
						
						table.repaint();
	
						if (stats[i][1] != "[n/a]" || stats[i][2] != "[n/s]" || stats[i][3] != "[n/s]") {
								
							PortScanner ps = new PortScanner();
							final ExecutorService es = Executors.newFixedThreadPool(500);
							final int timeout = 20;
							final List<Future<ScanResult>> futures = new ArrayList<>();
								
							for (int port = 1; port <= 1024; port++) {
								futures.add(ps.portIsOpen(es, fixedip + i, port, timeout));
							}
							try {
								es.awaitTermination(80L, TimeUnit.MICROSECONDS);
							} catch (InterruptedException e1) {
									
								e1.printStackTrace();
							}
						
							int openPorts = 0;
							
							for (final Future<ScanResult> f : futures) {
								try {
									if (f.get().isOpen()) {
										openPorts++;
										stats[i][4] = (stats[i][4] == null)?f.get().getPort(): (stats[i][4].toString() + "," +f.get().getPort());
										table.repaint();
									}
								} catch (InterruptedException | ExecutionException e1) {
							
									e1.printStackTrace();
								}
							}
						} else {
							
							stats[i][4] = "[n/s]";
							table.repaint();
						}
						if(stats[i][4] == null) {
				
							stats[i][4] = "[n/s]";
						}
						
	
						BarThread progressbar = new BarThread(progressBar);
						progressbar.start();
						
					}
						
					start.setIcon(new ImageIcon("start.png"));
					start.setText("  Start");
					
				}).start();
					
			}
		});
	
		JLabel label_5 = new JLabel("  ");
		toolbar2.add(label_5);
		
		JButton button_1 = new JButton("");
		button_1.setIcon(new ImageIcon("menu.png"));
		toolbar2.add(button_1);
		
		JLabel label_7 = new JLabel("  ");
		toolbar2.add(label_7);
		
		JMenuBar menuBar = new JMenuBar();
		menuBar.setForeground(UIManager.getColor("MenuItem.foreground"));
		menuBar.setBackground(UIManager.getColor("MenuBar.background"));
		jframe.setJMenuBar(menuBar);
		
		JMenu mnScan = new JMenu("Scan");
		menuBar.add(mnScan);
		
		JMenuItem mntmLoadFromFile = new JMenuItem("Load from file...");
		mnScan.add(mntmLoadFromFile);
		
		JMenuItem mntmExportAll = new JMenuItem("Export all...");
		mnScan.add(mntmExportAll);
		
		JMenuItem mntmExportSelectoin = new JMenuItem("Export selectoin...");
		mnScan.add(mntmExportSelectoin);
		
		mnScan.addSeparator();
		
		JMenuItem mntmQuitCtrlq = new JMenuItem("Quit");
		mnScan.add(mntmQuitCtrlq);
		
		JMenu mnGoTo = new JMenu("Go to");
		menuBar.add(mnGoTo);
		
		JMenuItem mntmNextAliveHost = new JMenuItem("Next alive host");
		mnGoTo.add(mntmNextAliveHost);
		
		JMenuItem mntmNextOpenPort = new JMenuItem("Next open port");
		mnGoTo.add(mntmNextOpenPort);
		
		JMenuItem mntmNextDeadHost = new JMenuItem("Next dead host");
		mnGoTo.add(mntmNextDeadHost);
		
		mnGoTo.addSeparator();
		
		JMenuItem mntmPreviousAliveHost = new JMenuItem("Previous alive host");
		mnGoTo.add(mntmPreviousAliveHost);
		
		JMenuItem mntmPreviousOpenPort = new JMenuItem("Previous open port");
		mnGoTo.add(mntmPreviousOpenPort);
		
		JMenuItem mntmPreviousDeadHost = new JMenuItem("Previous dead host");
		mnGoTo.add(mntmPreviousDeadHost);
		
		mnGoTo.addSeparator();
		
		JMenuItem mntmFindCtrlf = new JMenuItem("Find...");
		mnGoTo.add(mntmFindCtrlf);
		
		JMenu mnCommands = new JMenu("Commands");
		menuBar.add(mnCommands);
		
		JMenuItem mntmShowDetails = new JMenuItem("Show details");
		mnCommands.add(mntmShowDetails);
		
		mnCommands.addSeparator();
		
		JMenuItem mntmRescanIpsCtrlr = new JMenuItem("Rescan IP(s)");
		mnCommands.add(mntmRescanIpsCtrlr);
		
		JMenuItem mntmDeleteIpsDel = new JMenuItem("Delete IP(s)");
		mnCommands.add(mntmDeleteIpsDel);
		
		mnCommands.addSeparator();
		
		JMenuItem mntmCopyIpCtrlc = new JMenuItem("Copy IP");
		mnCommands.add(mntmCopyIpCtrlc);
		
		JMenuItem mntmCopyDetails = new JMenuItem("Copy details");
		mnCommands.add(mntmCopyDetails);
		
		mnCommands.addSeparator();
		
		JMenu mnOpen = new JMenu("Open");
		mnCommands.add(mnOpen);
		
		JMenuItem mntmEditOpeners = new JMenuItem("Edit openers...");
		mnOpen.add(mntmEditOpeners);
		
		mnOpen.addSeparator();
		
		JMenuItem mntmWindowsSharesCtrl = new JMenuItem("Windows Shares");
		mnOpen.add(mntmWindowsSharesCtrl);
		
		JMenuItem mntmWebBrowserCtrl = new JMenuItem("Web Browser");
		mnOpen.add(mntmWebBrowserCtrl);
		
		JMenuItem mntmFtpCtrl = new JMenuItem("FTP");
		mnOpen.add(mntmFtpCtrl);
		
		JMenuItem mntmTelnetCtrl = new JMenuItem("Telnet");
		mnOpen.add(mntmTelnetCtrl);
		
		JMenuItem mntmPingCtrl = new JMenuItem("Ping");
		mnOpen.add(mntmPingCtrl);
		
		JMenuItem mntmTraceRouteCtrl = new JMenuItem("Trace route");
		mnOpen.add(mntmTraceRouteCtrl);
		
		JMenuItem mntmGeoLocateCtrl = new JMenuItem("Geo locate");
		mnOpen.add(mntmGeoLocateCtrl);
		
		JMenuItem mntmEmailSampleCtrl = new JMenuItem("E-mail sample");
		mnOpen.add(mntmEmailSampleCtrl);
	
		JMenu mnFavorits = new JMenu("Favorits");
		menuBar.add(mnFavorits);
		
		JMenuItem mntmAddCurrentCtrld = new JMenuItem("Add current...");
		mnFavorits.add(mntmAddCurrentCtrld);
		
		JMenuItem mntmManageFavorites = new JMenuItem("Manage favorites...");
		mnFavorits.add(mntmManageFavorites);
		
		JMenu mnTools = new JMenu("Tools");
		menuBar.add(mnTools);
		
		JMenuItem mntmPrefeerencesCtrlshiftp = new JMenuItem("Preferences...");
		mnTools.add(mntmPrefeerencesCtrlshiftp);
		
		JMenuItem mntmFetchersCtrlshifto = new JMenuItem("Fetchers...");
		mnTools.add(mntmFetchersCtrlshifto);
		
		mnTools.addSeparator();
		
		JMenu mnSelection = new JMenu("Selection");
		mnTools.add(mnSelection);
		
		JMenuItem mntmAliveHost = new JMenuItem("Alive host");
		mnSelection.add(mntmAliveHost);
		
		JMenuItem mntmDeadHost = new JMenuItem("Dead host");
		mnSelection.add(mntmDeadHost);
		
		JMenuItem mntmWithOpenPorts = new JMenuItem("With open ports");
		mnSelection.add(mntmWithOpenPorts);
		
		JMenuItem mntmWithoutOpenPorts = new JMenuItem("Without open ports");
		mnSelection.add(mntmWithoutOpenPorts);
		
		mnSelection.addSeparator();
		JMenuItem mntmInvertSelectionCtrli = new JMenuItem("Invert selection");
		mnSelection.add(mntmInvertSelectionCtrli);
		
		JMenuItem mntmScanStatisticsCtrlt = new JMenuItem("Scan statistics");
		mnTools.add(mntmScanStatisticsCtrlt);
		
		JMenu mnHelp = new JMenu("Help");
		menuBar.add(mnHelp);
		
		JMenuItem mntmGettingStsrtedF = new JMenuItem("Getting Stsrted");
		mnHelp.add(mntmGettingStsrtedF);
		
		mnHelp.addSeparator();
		
		JMenuItem mntmOfficialWecsite = new JMenuItem("Official Website");
		mnHelp.add(mntmOfficialWecsite);
		
		JMenuItem mntmFaq = new JMenuItem("FAQ");
		mnHelp.add(mntmFaq);
		
		JMenuItem mntmReportAnIssue = new JMenuItem("Report an issue");
		mnHelp.add(mntmReportAnIssue);
		
		JMenuItem mntmPlugins = new JMenuItem("Plugins");
		mnHelp.add(mntmPlugins);
		
		mnHelp.addSeparator();
		
		JMenuItem mntmCommandlineUsage = new JMenuItem("Command-line usage");
		mnHelp.add(mntmCommandlineUsage);
		
		mnHelp.addSeparator();
		
		JMenuItem mntmCheckForNewer = new JMenuItem("Check for newer version...");
		mnHelp.add(mntmCheckForNewer);
		
		mnHelp.addSeparator();
		
		JMenuItem mntmAbout = new JMenuItem("About");
		mnHelp.add(mntmAbout);
		
		jframe.setVisible(true);
		
	}

	private Object[][] getNetworkStats() {
		
			Object[][] results = new Object[254][5];
			return results;
	}

	public static void main(String[] args) throws UnknownHostException {
				new IPScanner();
	}
}

 class Pinging extends Thread {
	 
	private Object[] msg;
	private String ip;

	public Pinging(String ip) {
		this.ip = ip;
		msg = new Object[5];
	}

	public void run() {
		InputStream is = null;
		BufferedReader br = null;
		try {
			Runtime run = Runtime.getRuntime();
			Process p = run.exec("ping -a " + ip);
			msg[0] = ip;
			is = p.getInputStream();
			br = new BufferedReader(new InputStreamReader(is));
			String line = null;
			while ((line = br.readLine()) != null) {

				if (line.indexOf("[") >= 0) {
					msg[3] = line.substring(5, line.indexOf("["));
				}
				if (line.indexOf("ms") >= 0) {
					
					Pattern pattern =
					Pattern.compile("(\\d+ms)(\\s+)(TTL=\\d+)",Pattern.CASE_INSENSITIVE);
					Matcher matcher = pattern.matcher(line);
					msg[1] = line.substring(line.indexOf("ms") - 1, line.indexOf("ms") + 2);
					msg[2] = line.substring(line.indexOf("TTL=") + 4, line.length());
					break;
				}
				if (line != null)

				{
				}
			}
		} catch (IOException e) {

			e.printStackTrace();
		}

	}
 
	
	public Object[] getMsg() {
		try {
			join();
		} catch (InterruptedException e) {

			e.printStackTrace();
		}
		
		return msg;
	}
 }
 class PortScanner  {
	
	void PortScanner() throws InterruptedException, ExecutionException {
		
		final ExecutorService es = Executors.newFixedThreadPool(20);
		final String ip = "127.0.0.1";
		final int timeout = 200;
		final List<Future<ScanResult>> futures = new ArrayList<>();
		
		for (int port=1; port<=1024; port++) {
			
			futures.add(portIsOpen(es, ip, port, timeout));
		}
		es.awaitTermination(200L, TimeUnit.MILLISECONDS);
		
		int openPorts = 0;
		
		for (final Future<ScanResult> f : futures) {
			if (f.get().isOpen()) {
				openPorts++;			
			}
			
		}

	}
	
	public Future<ScanResult> portIsOpen(final ExecutorService es, final String ip, 
											final int port, final int timeout) {
	
		return es.submit(new Callable<ScanResult>() {
			
			public ScanResult call() {
				
				try {
						Socket socket = new Socket();
						socket.connect(new InetSocketAddress(ip, port), timeout);
						socket.close();
						return new ScanResult(port, true);
				} catch (Exception ex) {
						return new ScanResult(port, false);
				}
			}
		});
	}
 }
 
class ScanResult {
	
	private int port;
	
	private boolean isOpen;
	
	public ScanResult(int port, boolean isOpen) {
		
		super();
		this.port = port;
		this.isOpen = isOpen;
	}
		
		public int getPort() {
			return port;
		}
		
		public void setPort(int port) {
			this.port = port;
		}
		
		public boolean isOpen() {
			return isOpen;
		}
		
		public void setOpen(boolean isOpen) {
			this.isOpen = isOpen;
		}
		
		
	}

class BarThread extends Thread {
	  private int DELAY = 100;

	  JProgressBar progressBar;

	  public BarThread(JProgressBar bar) {
	    progressBar = bar;
	  }

	  public void run() {
	    int minimum = progressBar.getMinimum();
	    int maximum = progressBar.getMaximum();
	    for (int i = minimum; i < maximum; i++) {
	      try {
	        int value = progressBar.getValue();
	        progressBar.setValue(value + 1);

	        Thread.sleep(DELAY);
	      } catch (InterruptedException ignoredException) {
	      }
	    }
	  }
}
 

