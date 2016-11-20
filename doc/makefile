FILE=dokumentace

do:$(FILE).tex
	pdflatex $(FILE).tex
	bibtex $(FILE).aux
	pdflatex $(FILE).tex
	mv ${FILE}.pdf manual.pdf

clean:
	rm -rf *.aux *.dvi *.ps *.blg *.bbl *.log *.out *.lof *.toc *.lot
purge:clean
	rm -rf *.pdf
