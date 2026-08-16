import { LockIcon, SearchIcon, PoisonIcon, ProbeIcon } from './Icons';

export default function OverviewPanel() {
  return (
    <section className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-10 mb-8 shadow-xs relative overflow-hidden">
      <div className="flex flex-col lg:flex-row items-center justify-between gap-8 relative z-10">
        <div className="max-w-3xl">
          {/* OWASP LLM08 Badge */}
          <span className="inline-block px-4 py-1.5 rounded-full bg-blue-50 text-blue-600 font-extrabold text-xs uppercase tracking-wider mb-4 border border-blue-200/80 shadow-2xs">
            OWASP LLM08
          </span>

          {/* Heading */}
          <h2 className="text-4xl sm:text-5xl font-black text-slate-900 mb-3 tracking-tight leading-tight">
            Vector &amp; Embedding Security
          </h2>
          <div className="w-16 h-1.5 bg-blue-600 rounded-full mb-6 shadow-xs" />

          {/* Description */}
          <p className="text-slate-600 text-base sm:text-lg leading-relaxed mb-2 font-normal">
            Modern AI systems store knowledge as numerical vectors in a vector database. <strong className="text-slate-900 font-bold">OWASP LLM08</strong> identifies the risk that these <strong className="text-slate-900 font-bold">embeddings can be exploited</strong>: leaking private data, <strong className="text-slate-900 font-bold">being poisoned</strong> to manipulate AI outputs, or exposing tenant information across security boundaries. This scanner automatically audits a live <strong className="text-slate-900 font-bold">Qdrant</strong> vector store across all attack classes.
          </p>
        </div>

        {/* Right Graphic Illustration */}
        <div className="shrink-0 w-64 h-56 sm:w-88 sm:h-64 relative flex items-center justify-center">
          <img
            src="/hero_3d_shield_platform.png"
            alt="3D Vector Security Shield Platform"
            className="w-full h-full object-contain contrast-105 transform hover:scale-105 transition-transform duration-500"
          />
        </div>
      </div>

      {/* 4 Feature Cards Grid with Permanent Default Light Blue Border */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mt-10">
        {[
          {
            q: "Can I see data I shouldn't?",
            badgeBg: "bg-blue-50/80 border-blue-200",
            icon: <LockIcon className="w-6 h-6 text-blue-600" />,
            desc: "ACL / tenant isolation: can one tenant access another's vectors?",
          },
          {
            q: "Can I recover private info from embeddings?",
            badgeBg: "bg-emerald-50/80 border-emerald-200",
            icon: <SearchIcon className="w-6 h-6 text-emerald-600" />,
            desc: "Embedding inversion: can raw text be reconstructed from a vector?",
          },
          {
            q: "Can I make bad content appear too often?",
            badgeBg: "bg-amber-50/80 border-amber-200",
            icon: <PoisonIcon className="w-6 h-6 text-amber-600" />,
            desc: "Poisoning: does injected content get over-retrieved?",
          },
          {
            q: "Can I manipulate what the RAG retrieves?",
            badgeBg: "bg-purple-50/80 border-purple-200",
            icon: <ProbeIcon className="w-6 h-6 text-purple-600" />,
            desc: "Semantic drift / probing: can retrieval be steered by an adversary?",
          },
        ].map(({ q, badgeBg, icon, desc }) => (
          <div
            key={q}
            className="bg-white border-2 border-blue-400/80 rounded-3xl p-6 shadow-sm shadow-blue-500/10 hover:border-blue-600 hover:shadow-md transition-all duration-200 flex flex-col justify-between group cursor-pointer"
          >
            <div>
              <div className={`w-12 h-12 rounded-full border flex items-center justify-center mb-5 ${badgeBg}`}>
                {icon}
              </div>
              <h4 className="text-slate-900 font-bold text-base mb-2 leading-snug">{q}</h4>
              <p className="text-slate-500 text-xs sm:text-sm leading-relaxed">{desc}</p>
            </div>
            <div className="mt-6 flex justify-end">
              <span className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center shadow-sm shadow-blue-500/30 group-hover:bg-blue-700 group-hover:scale-110 transition-all duration-200">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 5l7 7-7 7" />
                </svg>
              </span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
