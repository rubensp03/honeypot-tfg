import React, { useEffect, useState, useMemo } from 'react';
import { parseData, type Connection } from './utils/parser';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { Shield, Activity, Globe, Server } from 'lucide-react';

function App() {
  const [data, setData] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/data.txt')
      .then(async res => {
        if (!res.ok) throw new Error(`Failed to load data: ${res.statusText}`);
        return res.text();
      })
      .then(text => {
        try {
          console.log("Data loaded, length:", text.length);
          const parsed = parseData(text);
          console.log("Parsed connections:", parsed.length);
          setData(parsed);
          setLoading(false);
        } catch (e: any) {
          console.error("Parse error:", e);
          setError(e.message);
          setLoading(false);
        }
      })
      .catch(err => {
        console.error("Fetch error:", err);
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const stats = useMemo(() => {
    const inbound = data.filter(c => c.isInbound);
    const total = inbound.length;

    // Ports
    const portCounts: Record<number, number> = {};
    inbound.forEach(c => {
      portCounts[c.dstPort] = (portCounts[c.dstPort] || 0) + 1;
    });
    const sortedPorts = Object.entries(portCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([port, count]) => ({ port: parseInt(port), count }));

    // Attackers
    const attackerCounts: Record<string, number> = {};
    inbound.forEach(c => {
      attackerCounts[c.srcIP] = (attackerCounts[c.srcIP] || 0) + 1;
    });
    const sortedAttackers = Object.entries(attackerCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([ip, count]) => ({ ip, count }));

    return {
      total,
      uniqueAttackers: Object.keys(attackerCounts).length,
      topPorts: sortedPorts,
      topAttackers: sortedAttackers
    };
  }, [data]);

  // Pagination for full list
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 100;
  const totalPages = Math.ceil(data.length / PAGE_SIZE);
  const currentData = data.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  if (loading) return <div className="min-h-screen bg-slate-900 text-white flex items-center justify-center">Loading Data...</div>;
  if (error) return <div className="min-h-screen bg-slate-900 text-red-400 flex items-center justify-center">Error: {error}</div>;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 selection:bg-indigo-500 selection:text-white">
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">Honeypot Analysis</h1>
        <p className="text-slate-400 mt-2">Dynamic analysis of <code className="bg-slate-800 px-1 rounded">data.txt</code></p>
      </header>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatCard icon={<Shield className="text-indigo-400" />} label="Total Inbound Attacks" value={stats.total.toLocaleString()} />
        <StatCard icon={<Globe className="text-cyan-400" />} label="Unique Attackers" value={stats.uniqueAttackers.toLocaleString()} />
        <StatCard icon={<Server className="text-purple-400" />} label="Most Attacked Port" value={stats.topPorts[0]?.port.toString() || 'N/A'} sub={stats.topPorts[0]?.count.toLocaleString() + ' hits'} />
        <StatCard icon={<Activity className="text-rose-400" />} label="Total Connections" value={data.length.toLocaleString()} />
      </div>

      {/* Charts & Tables Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <Card title="Top Attacked Ports">
          <div className="flex flex-col h-[600px]">
            <div className="h-64 mb-6 flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.topPorts.slice(0, 20)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="port" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" />
                  <Tooltip
                    cursor={{ fill: '#334155', opacity: 0.4 }}
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="count" fill="#818cf8" radius={[4, 4, 0, 0]}>
                    {stats.topPorts.slice(0, 20).map((_, index) => (
                      <Cell key={`cell-${index}`} fill={`hsl(${230 + index * 2}, 80%, 60%)`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="flex-1 overflow-auto border-t border-slate-800 pt-4">
              <h3 className="text-sm font-semibold text-slate-400 mb-3 sticky top-0 bg-slate-900/95 py-2">Top 100 Ports</h3>
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-slate-900 z-10">
                  <tr>
                    <th className="p-2 text-xs text-slate-500 uppercase">Rank</th>
                    <th className="p-2 text-xs text-slate-500 uppercase">Port</th>
                    <th className="p-2 text-xs text-slate-500 uppercase text-right">Hits</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.topPorts.slice(0, 100).map((p, i) => (
                    <tr key={p.port} className="hover:bg-slate-800/50 transition-colors border-b border-slate-800/50 last:border-0">
                      <td className="p-2 text-slate-500 text-sm">#{i + 1}</td>
                      <td className="p-2 font-mono text-purple-300 text-sm">{p.port}</td>
                      <td className="p-2 text-right text-slate-300 text-sm">{p.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Card>

        <Card title="Top Recurrent Attackers">
          <div className="h-[600px] overflow-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-slate-900 z-10">
                <tr>
                  <th className="p-3 border-b border-slate-700 text-slate-400 font-medium">Rank</th>
                  <th className="p-3 border-b border-slate-700 text-slate-400 font-medium">IP Address</th>
                  <th className="p-3 border-b border-slate-700 text-slate-400 font-medium text-right">Connections</th>
                </tr>
              </thead>
              <tbody>
                {stats.topAttackers.slice(0, 100).map((attacker, i) => (
                  <tr key={attacker.ip} className="hover:bg-slate-800/50 transition-colors border-b border-slate-800/50 last:border-0">
                    <td className="p-3 text-slate-500">#{i + 1}</td>
                    <td className="p-3 font-mono text-cyan-300">{attacker.ip}</td>
                    <td className="p-3 text-right text-slate-300">{attacker.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {/* Full Review */}
      <Card title="Connection Log Review">
        <div className="flex justify-between items-center mb-4">
          <div className="text-sm text-slate-400">
            Showing {((page - 1) * PAGE_SIZE) + 1} - {Math.min(page * PAGE_SIZE, data.length)} of {data.length.toLocaleString()}
          </div>
          <div className="flex gap-2">
            <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50 text-sm transition-colors">Prev</button>
            <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50 text-sm transition-colors">Next</button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm border-collapse">
            <thead>
              <tr className="bg-slate-900/50">
                <th className="p-3 border-b border-slate-700 text-slate-400">Time</th>
                <th className="p-3 border-b border-slate-700 text-slate-400">Direction</th>
                <th className="p-3 border-b border-slate-700 text-slate-400">Source</th>
                <th className="p-3 border-b border-slate-700 text-slate-400">Destination</th>
                <th className="p-3 border-b border-slate-700 text-slate-400">Protocol</th>
              </tr>
            </thead>
            <tbody>
              {currentData.map((conn) => (
                <tr key={conn.id} className="hover:bg-slate-800/50 border-b border-slate-800/50 transition-colors">
                  <td className="p-2 font-mono text-slate-300">{conn.timestamp}</td>
                  <td className="p-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${conn.isInbound ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'}`}>
                      {conn.isInbound ? 'ATTACK' : 'RESPONSE'}
                    </span>
                  </td>
                  <td className="p-2 font-mono text-slate-300">{conn.srcIP}:{conn.srcPort}</td>
                  <td className="p-2 font-mono text-slate-300">{conn.dstIP}:{conn.dstPort}</td>
                  <td className="p-2 text-slate-400 truncate max-w-xs font-mono text-xs">{conn.protocol}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

const StatCard = ({ icon, label, value, sub }: { icon: any, label: string, value: string, sub?: string }) => (
  <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 p-6 rounded-xl hover:border-indigo-500/50 transition-all hover:shadow-lg hover:shadow-indigo-500/10">
    <div className="flex items-center gap-4 mb-2">
      <div className="p-3 bg-slate-800/80 rounded-lg">{icon}</div>
      <div>
        <h3 className="text-slate-400 text-sm font-medium">{label}</h3>
        <p className="text-2xl font-bold text-white tracking-tight">{value}</p>

      </div>
    </div>
    {sub && <p className="text-xs text-slate-500 mt-1 pl-[3.25rem]">{sub}</p>}
  </div>
);

const Card = ({ title, children }: { title: string, children: React.ReactNode }) => (
  <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl p-6 flex flex-col hover:border-slate-700 transition-colors">
    <h2 className="text-xl font-semibold mb-6 flex items-center gap-2 text-slate-200">
      {title}
    </h2>
    <div className="flex-1">
      {children}
    </div>
  </div>
);

export default App;
