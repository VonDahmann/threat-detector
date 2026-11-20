package dz.univ.threat.service;

import dz.univ.threat.model.InputType;
import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * TEMPORARY STUB so that Person 3 can test message rules alone.
 * Person 2 writes the real UrlRuleAnalyzer: when it is merged, it REPLACES this file.
 * Only 3 rules here: HTTP (+30), IPv4 host (+40), '@' in authority (+40).
 */
public class UrlRuleAnalyzer implements Analyzer {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    @Override
    public ScanResult analyze(ScanItem item) {
        try {
            if (item == null || item.content() == null || item.content().isBlank()) {
                return ScanResult.notVerified(item, "Empty input");
            }
            URI uri = new URI(item.content().trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return ScanResult.notVerified(item, "Malformed URL");
            }
            int score = 0;
            List<String> reasons = new ArrayList<>();
            if (scheme.equalsIgnoreCase("http")) { score += 30; reasons.add("HTTP without encryption (+30)"); }
            if (IPV4.matcher(host).matches()) { score += 40; reasons.add("Host is an IP address (+40)"); }
            if (uri.getRawAuthority() != null && uri.getRawAuthority().contains("@")) {
                score += 40; reasons.add("'@' in the authority part (+40)");
            }
            score = Math.min(score, 100);
            return new ScanResult(item, ScoreMapper.map(score), score, List.copyOf(reasons), null);
        } catch (Exception e) {
            return ScanResult.notVerified(item, "Malformed URL");
        }
    }
}
