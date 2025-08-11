/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import dynamic from 'next/dynamic';

// --- Type Definitions ---
interface ArcData {
    startLat: number;
    startLng: number;
    endLat: number;
    endLng: number;
    color: string[];
    label: string;
    severity?: 'low' | 'medium' | 'high';
    sourceIp?: string;
    attackType?: string;
    timestamp?: string;
}

interface PointData {
    lat: number;
    lng: number;
    size: number;
    color: string;
    name: string;
    type?: 'city' | 'target' | 'source';
}

interface ThreatStats {
    total: number;
    high: number;
    medium: number;
    low: number;
    lastUpdate: string;
}

// --- Helper Data ---
const CITIES: Omit<PointData, 'size' | 'color' | 'type'>[] = [
    { lat: 40.7128, lng: -74.0060, name: 'New York' },
    { lat: 37.7749, lng: -122.4194, name: 'San Francisco' },
    { lat: 51.5074, lng: -0.1278, name: 'London' },
    { lat: 35.6895, lng: 139.6917, name: 'Tokyo' },
    { lat: 52.5200, lng: 13.4050, name: 'Berlin' },
    { lat: -33.8688, lng: 151.2093, name: 'Sydney' },
];

export default function Home() {
    // Dynamic import for Globe
    const Globe = useMemo(() => dynamic(() => import('react-globe.gl'), {
        ssr: false,
        loading: () => (
            <div className="flex items-center justify-center h-screen bg-gray-900">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
                    <p className="text-white text-lg">Loading Threat Intelligence Globe...</p>
                </div>
            </div>
        )
    }), []);

    // State management
    const globeEl = useRef<any>(null);
    const [arcsData, setArcsData] = useState<ArcData[]>([]);
    const [pointsData, setPointsData] = useState<PointData[]>([]);
    const [globeReady, setGlobeReady] = useState(false);
    const [hoverArc, setHoverArc] = useState<ArcData | undefined>();
    const [apiStatus, setApiStatus] = useState('Initializing threat detection systems...');
    const [threatStats, setThreatStats] = useState<ThreatStats>({
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
        lastUpdate: new Date().toISOString(),
    });
    const [isOnline, setIsOnline] = useState(true);

    // --- Helper Functions ---
    const updateThreatStats = (attacks: ArcData[]) => {
        const stats = attacks.reduce((acc, attack) => {
            acc.total++;
            if (attack.severity === 'high') acc.high++;
            else if (attack.severity === 'medium') acc.medium++;
            else acc.low++;
            return acc;
        }, { total: 0, high: 0, medium: 0, low: 0, lastUpdate: new Date().toISOString() });
        
        setThreatStats(stats);
    };

    const addTargetPoint = (lat: number, lng: number, name: string) => {
        setPointsData(current => {
            const exists = current.some(point => 
                Math.abs(point.lat - lat) < 0.1 && Math.abs(point.lng - lng) < 0.1
            );
            if (!exists) {
                return [...current, {
                    lat,
                    lng,
                    size: 0.3,
                    color: 'rgba(255, 165, 0, 0.8)',
                    name,
                    type: 'target' as const,
                }];
            }
            return current;
        });
    };

    // --- Effects ---

    // Initialize city points
    useEffect(() => {
        setPointsData(CITIES.map(city => ({
            ...city,
            size: 0.15,
            color: 'rgba(255, 255, 255, 0.6)',
            type: 'city' as const,
        })));
    }, []);

    // Enhanced API data fetching
    useEffect(() => {
        let mounted = true;

        const fetchThreatData = async () => {
            try {
                setIsOnline(true);
                const res = await fetch('/api/attacks', {
                    headers: {
                        'Cache-Control': 'no-cache',
                    },
                });
                
                if (!mounted) return;

                const data = await res.json();

                if (!res.ok) {
                    setApiStatus(`⚠️ API Error: ${data.error || 'Failed to fetch threat data'}`);
                    setIsOnline(false);
                    return;
                }

                if (data.message) {
                    setApiStatus(`✅ ${data.message}`);
                } else if (data.startLat) {
                    // Process successful attack data
                    const newAttack: ArcData = {
                        ...data,
                        timestamp: data.timestamp || new Date().toISOString(),
                    };

                    setApiStatus(`🚨 THREAT DETECTED: ${data.attackType || 'Malicious Activity'}`);
                    
                    setArcsData(currentArcs => {
                        const updatedArcs = [newAttack, ...currentArcs].slice(0, 25);
                        updateThreatStats(updatedArcs);
                        return updatedArcs;
                    });

                    // Add target point to globe
                    addTargetPoint(data.endLat, data.endLng, 'Target Location');

                    // Auto-focus on new attack
                    if (globeEl.current) {
                        setTimeout(() => {
                            globeEl.current.pointOfView({
                                lat: (data.startLat + data.endLat) / 2,
                                lng: (data.startLng + data.endLng) / 2,
                                altitude: 1.5,
                            }, 2000);
                        }, 500);
                    }
                }

            } catch (error) {
                if (!mounted) return;
                console.error('Fetch error:', error);
                setApiStatus('🔴 Connection Error: Unable to reach threat intelligence API');
                setIsOnline(false);
            }
        };

        // Initial fetch
        fetchThreatData();

        // Set up interval (every 8 seconds to respect API limits)
        const interval = setInterval(fetchThreatData, 8000);

        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, []);

    // Globe setup and controls
    useEffect(() => {
        if (globeReady && globeEl.current) {
            const controls = globeEl.current.controls();
            controls.autoRotate = true;
            controls.autoRotateSpeed = 0.3;
            controls.enableZoom = true;
            controls.enablePan = true;
            controls.minDistance = 200;
            controls.maxDistance = 1000;
            
            globeEl.current.pointOfView({ 
                lat: 20, 
                lng: 0, 
                altitude: 2.5 
            });
        }
    }, [globeReady]);

    // Auto-clear old attacks
    useEffect(() => {
        const cleanup = setInterval(() => {
            setArcsData(current => {
                const cutoff = Date.now() - (10 * 60 * 1000); // 10 minutes
                const filtered = current.filter(arc => {
                    const timestamp = new Date(arc.timestamp || '').getTime();
                    return timestamp > cutoff;
                });
                
                if (filtered.length !== current.length) {
                    updateThreatStats(filtered);
                }
                
                return filtered;
            });
        }, 30000); // Check every 30 seconds

        return () => clearInterval(cleanup);
    }, []);

    // --- Render ---
    return (
        <main className="bg-gray-900 text-white min-h-screen flex flex-col relative overflow-hidden">
            {/* Header with Stats */}
            <div className="absolute top-0 left-0 w-full z-20 p-4">
                <div className="flex flex-col lg:flex-row items-center justify-between">
                    <div className="text-center lg:text-left mb-2 lg:mb-0">
                        <h1 className="text-2xl md:text-3xl font-bold text-red-500 tracking-wider" 
                            style={{ textShadow: '0 0 10px rgba(255, 0, 0, 0.7)' }}>
                            🔴 Live Cyber Threat Intelligence
                        </h1>
                        <p className="text-gray-400 text-sm">
                            Real-time visualization powered by AbuseIPDB • Created by{' '}
                            <a 
                                href="https://meetpatel.live" 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 transition-colors underline"
                            >
                                Meet Patel
                            </a>
                        </p>
                    </div>
                    
                    {/* Threat Statistics */}
                    <div className="flex gap-4 text-sm">
                        <div className="bg-gray-800/70 px-3 py-1 rounded-lg border border-gray-700">
                            <span className="text-gray-400">Total:</span>
                            <span className="text-white ml-1 font-semibold">{threatStats.total}</span>
                        </div>
                        <div className="bg-red-900/70 px-3 py-1 rounded-lg border border-red-700">
                            <span className="text-red-300">High:</span>
                            <span className="text-white ml-1 font-semibold">{threatStats.high}</span>
                        </div>
                        <div className="bg-yellow-900/70 px-3 py-1 rounded-lg border border-yellow-700">
                            <span className="text-yellow-300">Med:</span>
                            <span className="text-white ml-1 font-semibold">{threatStats.medium}</span>
                        </div>
                        <div className="bg-blue-900/70 px-3 py-1 rounded-lg border border-blue-700">
                            <span className="text-blue-300">Low:</span>
                            <span className="text-white ml-1 font-semibold">{threatStats.low}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Connection Status */}
            <div className="absolute top-16 right-4 z-20">
                <div className={`px-3 py-1 rounded-full text-xs font-semibold ${
                    isOnline 
                        ? 'bg-green-800/70 text-green-300 border border-green-600' 
                        : 'bg-red-800/70 text-red-300 border border-red-600'
                }`}>
                    {isOnline ? '🟢 ONLINE' : '🔴 OFFLINE'}
                </div>
            </div>

            {/* Globe Container */}
            <div className="w-full h-screen pt-20">
                <Globe
                    ref={globeEl}
                    onGlobeReady={() => setGlobeReady(true)}
                    globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                    backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
                    
                    // Arc configuration
                    arcsData={arcsData}
                    arcColor="color"
                    arcDashLength={() => Math.random() * 0.4 + 0.1}
                    arcDashGap={() => Math.random() * 0.3 + 0.1}
                    arcDashAnimateTime={() => Math.random() * 2000 + 1000}
                    arcStroke={(arc: any) => arc.severity === 'high' ? 0.8 : 0.5}
                    onArcHover={(arc: any) => setHoverArc(arc as ArcData | undefined)}
                    
                    // Points configuration
                    pointsData={pointsData}
                    pointColor="color"
                    pointRadius="size"
                    pointLabel="name"
                    
                    // Enhanced arc labels
                    arcLabel={(d: any) => `
                        <div class="bg-gray-800 border border-gray-600 rounded-lg p-3 text-sm text-white max-w-xs">
                            <div class="font-bold text-${d.severity === 'high' ? 'red' : d.severity === 'medium' ? 'yellow' : 'blue'}-400 mb-1">
                                ${d.severity?.toUpperCase() || 'UNKNOWN'} SEVERITY THREAT
                            </div>
                            <div class="text-gray-300 space-y-1">
                                <div><strong>Type:</strong> ${d.attackType || 'Unknown'}</div>
                                <div><strong>Source IP:</strong> ${d.sourceIp || 'Hidden'}</div>
                                <div><strong>Time:</strong> ${d.timestamp ? new Date(d.timestamp).toLocaleTimeString() : 'Unknown'}</div>
                                <div class="text-xs text-gray-400 mt-2">${d.label}</div>
                            </div>
                        </div>
                    `}
                />
            </div>
            
            {/* Enhanced Footer */}
            <div className="absolute bottom-0 left-0 w-full z-20 p-4">
                <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
                    {/* Status Display */}
                    <div className="bg-gray-800/80 backdrop-blur-sm border border-gray-700 rounded-lg p-3 flex-1 max-w-md">
                        <div className="font-semibold text-sm mb-1">
                            {hoverArc ? 'Threat Details' : 'System Status'}
                        </div>
                        <div className={`text-sm ${
                            hoverArc 
                                ? 'text-red-400' 
                                : apiStatus.includes('Error') || apiStatus.includes('OFFLINE') 
                                    ? 'text-red-400' 
                                    : apiStatus.includes('THREAT') 
                                        ? 'text-orange-400' 
                                        : 'text-green-400'
                        }`}>
                            {hoverArc ? hoverArc.label : apiStatus}
                        </div>
                        {!hoverArc && threatStats.lastUpdate && (
                            <div className="text-xs text-gray-500 mt-1">
                                Last updated: {new Date(threatStats.lastUpdate).toLocaleTimeString()}
                            </div>
                        )}
                    </div>

                    {/* Controls */}
                    <div className="flex gap-2">
                        <button
                            onClick={() => {
                                if (globeEl.current) {
                                    globeEl.current.pointOfView({ lat: 20, lng: 0, altitude: 2.5 }, 1000);
                                }
                            }}
                            className="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded-lg text-xs font-medium transition-colors"
                        >
                            🌍 Reset View
                        </button>
                        <button
                            onClick={() => {
                                if (globeEl.current) {
                                    const controls = globeEl.current.controls();
                                    controls.autoRotate = !controls.autoRotate;
                                }
                            }}
                            className="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded-lg text-xs font-medium transition-colors"
                        >
                            ⏯️ Toggle Rotation
                        </button>
                    </div>
                </div>
            </div>
        </main>
    );
}