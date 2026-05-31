"use client";

import { useEffect, useId, useRef, useState } from "react";

let initialized = false;

// Mermaid renders client-side: MDX runs as a server component, so we hand the
// raw diagram source to this island and draw it after hydration.
export function Mermaid({ chart }: { chart: string }) {
	const ref = useRef<HTMLDivElement>(null);
	const id = useId().replace(/:/g, "_");
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		(async () => {
			const mermaid = (await import("mermaid")).default;
			if (!initialized) {
				mermaid.initialize({
					startOnLoad: false,
					theme: "dark",
					securityLevel: "strict",
					themeVariables: {
						background: "#16161a",
						primaryColor: "#16161a",
						primaryBorderColor: "#2a2a3a",
						primaryTextColor: "#ededed",
						lineColor: "#7c8cf8",
						fontFamily: "JetBrains Mono, ui-monospace, monospace",
					},
				});
				initialized = true;
			}
			try {
				const { svg } = await mermaid.render(`m_${id}`, chart);
				if (!cancelled && ref.current) ref.current.innerHTML = svg;
			} catch (e) {
				if (!cancelled) setError(e instanceof Error ? e.message : String(e));
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [chart, id]);

	if (error) {
		return <pre className="mermaid-error">{error}</pre>;
	}
	return <div className="mermaid-diagram" ref={ref} />;
}
