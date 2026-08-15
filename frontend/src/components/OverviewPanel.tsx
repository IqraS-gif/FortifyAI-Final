import React from 'react';

export default function OverviewPanel() {
  return (
    <section className="card mb-8 animate-fade-in relative overflow-hidden group">
      {/* Subtle background glow effect */}
      <div className="absolute top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-accent/20 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-opacity duration-1000"></div>

      <div className="flex items-start gap-5 relative z-10">
        <div className="shrink-0 w-14 h-14 rounded-2xl bg-gradient-to-br from-accent/20 to-accent-light/10 flex items-center justify-center text-3xl shadow-[0_0_15px_rgba(110,86,207,0.3)] animate-float">🛡️</div>
        <div>
          <h2 className="text-2xl font-extrabold text-white mb-2 tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">OWASP LLM08 — Vector &amp; Embedding Security</h2>
          <p className="text-gray-400 text-sm leading-relaxed max-w-3xl">
            Modern AI systems store knowledge as numerical vectors in a vector database. OWASP LLM08
            identifies the risk that these embeddings can be exploited — leaking private data, being
            poisoned to manipulate AI outputs, or exposing tenant information across security boundaries.
            This scanner automatically audits a live Qdrant vector store across all attack classes.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-8 relative z-10">
        {[
          { q: 'Can I see data I shouldn\'t?', icon: '🔐', desc: 'ACL / tenant isolation — can one tenant access another\'s vectors?' },
          { q: 'Can I recover private info from embeddings?', icon: '🔍', desc: 'Embedding inversion — can raw text be reconstructed from a vector?' },
          { q: 'Can I make bad content appear too often?', icon: '☣️', desc: 'Poisoning — does injected content get over-retrieved?' },
          { q: 'Can I manipulate what the RAG retrieves?', icon: '🎯', desc: 'Semantic drift / probing — can retrieval be steered by an adversary?' },
        ].map(({ q, icon, desc }, i) => (
          <div key={q} className="bg-surface-800/50 backdrop-blur border border-surface-600/50 rounded-xl p-5 hover:bg-surface-700/60 hover:-translate-y-1 hover:shadow-lg transition-all duration-300" style={{ animationDelay: `${i * 100}ms` }}>
            <span className="text-3xl drop-shadow-md">{icon}</span>
            <p className="text-gray-100 font-bold text-sm mt-3 mb-1.5">{q}</p>
            <p className="text-gray-500 text-xs leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

