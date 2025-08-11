/* eslint-disable @typescript-eslint/no-explicit-any */
// app/api/attacks/route.ts
import { NextResponse } from 'next/server';

// --- Configuration ---
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const ABUSEIPDB_CHECK_URL = 'https://api.abuseipdb.com/api/v2/check';
const ABUSEIPDB_REPORTS_URL = 'https://api.abuseipdb.com/api/v2/reports';

// Cache for geolocation data to avoid repeated API calls
const geoCache = new Map<string, any>();

// Known target locations (major cities/data centers)
const TARGET_LOCATIONS = [
    { lat: 40.7128, lng: -74.0060, city: 'New York', country: 'United States' },
    { lat: 37.7749, lng: -122.4194, city: 'San Francisco', country: 'United States' },
    { lat: 51.5074, lng: -0.1278, city: 'London', country: 'United Kingdom' },
    { lat: 35.6895, lng: 139.6917, city: 'Tokyo', country: 'Japan' },
    { lat: 52.5200, lng: 13.4050, city: 'Berlin', country: 'Germany' },
    { lat: -33.8688, lng: 151.2093, city: 'Sydney', country: 'Australia' },
    { lat: 1.3521, lng: 103.8198, city: 'Singapore', country: 'Singapore' },
];

// Common malicious IPs for demonstration (update these with real threat intelligence)
const DEMO_MALICIOUS_IPS = [
    '185.220.100.240',  // Known Tor exit node
    '45.148.10.35',     // Known malicious IP
    '118.25.6.39',      // Frequently reported
    '103.97.205.66',    // Known botnet IP
    '194.147.78.103',   // Suspicious activity
];

/**
 * Fetches geolocation data for a given IP address with caching
 */
async function getGeolocation(ip: string) {
    // Check cache first
    if (geoCache.has(ip)) {
        return geoCache.get(ip);
    }

    try {
        // Using ip-api.com (free tier: 1000 requests/month, 45 requests/minute)
        const response = await fetch(
            `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as`,
            {
                headers: {
                    'User-Agent': 'CyberThreatVisualizer/1.0'
                }
            }
        );
        
        if (!response.ok) {
            console.error(`Geolocation API failed: ${response.status}`);
            return null;
        }

        const data = await response.json();
        if (data.status === 'success') {
            const geoData = {
                lat: data.lat,
                lng: data.lon,
                city: data.city || 'Unknown',
                country: data.country || 'Unknown',
                countryCode: data.countryCode,
                isp: data.isp,
                org: data.org,
                as: data.as,
            };
            
            // Cache the result for 1 hour
            geoCache.set(ip, geoData);
            setTimeout(() => geoCache.delete(ip), 60 * 60 * 1000);
            
            return geoData;
        }
        return null;
    } catch (error) {
        console.error('Geolocation error:', error);
        return null;
    }
}

/**
 * Fetch recent reports from AbuseIPDB
 */
async function getRecentReports() {
    if (!ABUSEIPDB_API_KEY) return null;

    try {
        // Get reports from the last 24 hours
        const response = await fetch(`${ABUSEIPDB_REPORTS_URL}?confidenceMinimum=75&maxAgeInDays=1&page=1&perPage=25`, {
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            console.error(`AbuseIPDB reports failed: ${response.status}`);
            return null;
        }

        const data = await response.json();
        return data.data || [];
    } catch (error) {
        console.error('AbuseIPDB reports error:', error);
        return null;
    }
}

/**
 * Check if an IP is malicious using AbuseIPDB
 */
async function checkMaliciousIp(ip: string) {
    if (!ABUSEIPDB_API_KEY) return null;

    try {
        const response = await fetch(`${ABUSEIPDB_CHECK_URL}?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            console.error(`AbuseIPDB check failed: ${response.status}`);
            return null;
        }

        const { data } = await response.json();
        return data;
    } catch (error) {
        console.error('AbuseIPDB check error:', error);
        return null;
    }
}

/**
 * Get attack type based on abuse categories
 */
function getAttackType(categories: number[]): string {
    const categoryMap: Record<number, string> = {
        3: 'Fraud Orders',
        4: 'DDoS Attack',
        5: 'FTP Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open Proxy',
        10: 'Web Spam',
        11: 'Email Spam',
        12: 'Blog Spam',
        13: 'VPN IP',
        14: 'Port Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute-Force',
        19: 'Bad Web Bot',
        20: 'Exploited Host',
        21: 'Web App Attack',
        22: 'SSH',
        23: 'IoT Targeted',
    };

    if (!categories || categories.length === 0) return 'Suspicious Activity';
    return categories.map(cat => categoryMap[cat] || 'Unknown').join(', ');
}

/**
 * Generate attack color based on severity
 */
function getAttackColor(abuseScore: number): string[] {
    if (abuseScore >= 90) {
        return ['rgba(255, 0, 0, 0.9)', 'rgba(255, 50, 0, 0.9)']; // Critical - Red
    } else if (abuseScore >= 75) {
        return ['rgba(255, 100, 0, 0.8)', 'rgba(255, 150, 0, 0.8)']; // High - Orange
    } else if (abuseScore >= 50) {
        return ['rgba(255, 200, 0, 0.7)', 'rgba(255, 255, 0, 0.7)']; // Medium - Yellow
    } else {
        return ['rgba(100, 149, 237, 0.6)', 'rgba(135, 206, 250, 0.6)']; // Low - Blue
    }
}

/**
 * Main GET handler
 */
export async function GET() {
    try {
        if (!ABUSEIPDB_API_KEY) {
            return NextResponse.json({ 
                error: 'AbuseIPDB API key not configured. Please set ABUSEIPDB_API_KEY environment variable.' 
            }, { status: 500 });
        }

        // Strategy 1: Try to get recent reports first
        let sourceIp: string | null = null;
        let abuseData: any = null;

        const recentReports = await getRecentReports();
        if (recentReports && recentReports.length > 0) {
            // Pick a random recent report
            const randomReport = recentReports[Math.floor(Math.random() * recentReports.length)];
            sourceIp = randomReport.ipAddress;
            abuseData = randomReport;
        } else {
            // Strategy 2: Fallback to checking known malicious IPs
            const randomIp = DEMO_MALICIOUS_IPS[Math.floor(Math.random() * DEMO_MALICIOUS_IPS.length)];
            const checkResult = await checkMaliciousIp(randomIp);
            
            if (checkResult && checkResult.abuseConfidenceScore > 25) {
                sourceIp = randomIp;
                abuseData = checkResult;
            }
        }

        if (!sourceIp || !abuseData) {
            return NextResponse.json({ 
                message: 'No significant threats detected in current scan.' 
            });
        }

        // Get geolocation for source IP
        const sourceGeo = await getGeolocation(sourceIp);
        if (!sourceGeo) {
            return NextResponse.json({ 
                error: 'Could not geolocate threat source.' 
            }, { status: 500 });
        }

        // Select random target
        const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];

        // Generate attack data
        const attackType = getAttackType(abuseData.categories || []);
        const attackColor = getAttackColor(abuseData.abuseConfidenceScore || 50);
        
        const attack = {
            startLat: sourceGeo.lat,
            startLng: sourceGeo.lng,
            endLat: target.lat,
            endLng: target.lng,
            color: attackColor,
            label: `${attackType} | ${sourceGeo.city}, ${sourceGeo.country} → ${target.city} | Score: ${abuseData.abuseConfidenceScore}% | ISP: ${sourceGeo.isp}`,
            severity: abuseData.abuseConfidenceScore >= 75 ? 'high' : 
                     abuseData.abuseConfidenceScore >= 50 ? 'medium' : 'low',
            sourceIp: sourceIp,
            attackType: attackType,
            timestamp: new Date().toISOString(),
        };

        return NextResponse.json(attack);

    } catch (error) {
        console.error('API Error:', error);
        return NextResponse.json({ 
            error: 'Internal server error while fetching threat data.' 
        }, { status: 500 });
    }
}