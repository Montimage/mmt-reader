# Per-source coverage table from concatenated `gcov -b` summaries (make coverage).
# Expects blocks shaped like:
#   File 'core/engine.c'
#   Lines executed:88.10% of 42
#   Branches executed:75.00% of 24
#   Taken at least once:66.67% of 24
# A source covered by several test binaries keeps its best (max) percentage —
# the union approximation across suites.
BEGIN { n = 0 }
/^File '/ {
	f = $0
	sub(/^File '/, "", f)
	sub(/'$/, "", f)
	if (f !~ /^tests\// && !(f in seen)) { seen[f] = 1; order[++n] = f }
	cur = f
	pending = 1
	next
}
cur != "" && pending == 1 && /^Lines executed:/ {
	pct = $2; sub(/^executed:/, "", pct); sub(/%$/, "", pct)
	cnt = $4 + 0
	if (!(cur in bl) || pct + 0 > bl[cur]) { bl[cur] = pct + 0; cl[cur] = cnt }
	pending = 0
}
cur != "" && /^Taken at least once:/ {
	pct = $4; sub(/^once:/, "", pct); sub(/%$/, "", pct)
	cnt = $6 + 0
	if (!(cur in bb) || pct + 0 > bb[cur]) { bb[cur] = pct + 0; cb[cur] = cnt }
}
cur != "" && /^No branches/ {
	if (!(cur in bb)) { bb[cur] = -1; cb[cur] = 0 }
}
/^Creating /  { cur = ""; pending = 0 }
END {
	printf "%-26s %10s %12s\n", "Source", "Line %", "Branch %"
	tl = tc = tb = tbc = 0; hasb = 0
	for (i = 1; i <= n; i++) {
		f = order[i]
		l = (f in bl) ? bl[f] : -1
		b = (f in bb) ? bb[f] : -1
		printf "%-26s %10s %12s\n", f,
			(l < 0 ? "n/a" : sprintf("%.2f%%", l)),
			(b < 0 ? "n/a" : sprintf("%.2f%%", b))
		if (l >= 0) { tl += cl[f]; tc += bl[f] * cl[f] / 100 }
		if (b >= 0 && cb[f] > 0) { tb += cb[f]; tbc += bb[f] * cb[f] / 100; hasb = 1 }
	}
	if (tl > 0)
		printf "%-26s %10.2f%% %12s\n", "TOTAL", 100 * tc / tl,
			(hasb ? sprintf("%.2f%%", 100 * tbc / tb) : "n/a")
}
