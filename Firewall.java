import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class Firewall {

	static Set<Rule> RuleHashSet = new HashSet<Rule>();

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Firewall  firewall = new Firewall("F:/MSSE/Interview/Illumio/inputfile.csv");
		boolean test1 = firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2");
		boolean test2 = firewall.accept_packet("inbound", "tcp", 80, "192.168.1.322");
		boolean test3 = firewall.accept_packet("outbound", "tcp", 11000, "192.168.10.11");
		boolean test4 = firewall.accept_packet("outbound", "tcp", 11000, "192.168.10.211");
		boolean test5 = firewall.accept_packet("outbound", "tcp", 20000, "192.168.10.11");
		boolean test6 = firewall.accept_packet("inbound", "udp", 53, "192.168.1.1");
		boolean test7 = firewall.accept_packet("inbound", "udp", 53, "192.168.2.6");
		boolean test8 = firewall.accept_packet("inbound", "udp", 53, "192.168.2.5");
		boolean test9 = firewall.accept_packet("outbound", "udp", 2000, "52.12.48.92");
		boolean test10 = firewall.accept_packet("outbound", "udp", 2001, "52.12.48.92");
		boolean test11 = firewall.accept_packet("inbound", "tcp", 673, "123.45.56.83");

		System.out.println(test1);
		System.out.println(test2);
		System.out.println(test3);
		System.out.println(test4);
		System.out.println(test5);
		System.out.println(test6);
		System.out.println(test7);
		System.out.println(test8);
		System.out.println(test9);
		System.out.println(test10);
		System.out.println(test11);

	}
	
	
public Firewall (String csvFile) {
	//Reading Data from CSV from geeksforgeeks.
		String line = "";
		String cvsSplitBy = ",";
		String[] rule = null;

		try {
			BufferedReader br = new BufferedReader(new FileReader(csvFile));
			while ((line = br.readLine()) != null) {
				rule = line.split(cvsSplitBy);
				if (rule[2].contains("-")) { // Ports with Range
					String[] portRange = rule[2].split("-");
					int minPortRange = Integer.parseInt(portRange[0]);
					int maxPortRange = Integer.parseInt(portRange[1]);
					int portRanges = maxPortRange - minPortRange;
					
					if (rule[3].contains("-")) {// IPS and Ports with Range
						String[] IPRange = rule[3].split("-");
						long minIPRange = Long.parseLong(IPRange[0].replaceAll("\\.", ""));
						long maxIPRange = Long.parseLong(IPRange[1].replaceAll("\\.", ""));
						long IPRanges = maxIPRange - minIPRange;
						// Add Rule with Port Range and IP Range
						for (int i = 0; i <= portRanges; i++) {
							for (int j = 0; j <= IPRanges; j++) {
								Rule currentRule = new Rule(rule[0], rule[1],minPortRange + i, minIPRange + j);
								RuleHashSet.add(currentRule);
							}
						}
					}
					// Add Rule with Port Range
					for (int i = 0; i <= portRanges; i++) {
						Rule currentRule = new Rule(rule[0], rule[1],minPortRange + i, rule[3]);
						RuleHashSet.add(currentRule);
					}
				} else if (rule[3].contains("-")) {
					String[] IPRange = rule[3].split("-");
					long minIPRange = Long.parseLong(IPRange[0].replaceAll("\\.", ""));
					long maxIPRange = Long.parseLong(IPRange[1].replaceAll("\\.", ""));
					long IPRanges = maxIPRange - minIPRange;
					for (int j = 0; j <= IPRanges; j++) {
						Rule currentRule = new Rule(rule[0], rule[1], rule[2],minIPRange + j);
						RuleHashSet.add(currentRule);
					}
				} else {
					// Add Rule without Port and IP range
					Rule currentRule = new Rule(rule[0], rule[1], rule[2],rule[3]);
					RuleHashSet.add(currentRule);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean accept_packet(String direction, String protocol,int port, String ip_address) {
		Rule newRule = new Rule(direction, protocol, port, ip_address);
		if (RuleHashSet.contains(newRule))
			return true;
		else
			return false;
	}
}

class Rule {
	protected String direction;
	protected String protocol;
	protected int port;
	protected long ip_address;

	public Rule(String direction, String protocol, int port, long ip_address) {
		// TODO Auto-generated constructor stub
		this.direction = direction;
		this.protocol = protocol;
		this.port = port;
		this.ip_address = ip_address;
	}

	public Rule(String direction, String protocol, int port, String ip_address) {
		// TODO Auto-generated constructor stub
		this.direction = direction;
		this.protocol = protocol;
		this.port = port;
		this.ip_address = Long.parseLong(ip_address.replaceAll("\\.", "")); // convert string ip_address to a number
		}

	public Rule(String direction, String protocol, String port,String ip_address) {
		// TODO Auto-generated constructor stub
		this.direction = direction;
		this.protocol = protocol;
		this.port = Integer.parseInt(port);
		this.ip_address = Long.parseLong(ip_address.replaceAll("\\.", ""));
	}

	public Rule(String direction, String protocol, String port, long ip_address) {
		// TODO Auto-generated constructor stub
		this.direction = direction;
		this.protocol = protocol;
		this.port = Integer.parseInt(port);
		this.ip_address = ip_address;
	}

	/**
	 * This is overwritten in order to state that 2 network rule are similar
	 * when direction, protocol, port and IP address are same.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!(obj instanceof Rule))
			return false;
		Rule networkRule = (Rule) obj;
		return direction.equals(networkRule.direction)
				&& protocol.equals(networkRule.protocol)
				&& port == networkRule.port
				&& ip_address == networkRule.ip_address;
	}

	@Override
	public String toString() {
		return this.direction + ", " + this.protocol + ", "+ Integer.toString(this.port) + ", "+ Long.toString(this.ip_address);
	}

	public int hashCode() {
		long hash = 31 * (this.ip_address + this.port + this.direction.hashCode() + this.protocol.hashCode()); // to get unique key from components																	
		return Long.valueOf(hash).hashCode();
	}

}
