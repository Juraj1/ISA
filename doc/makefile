FILE=dokumentace

do:$(FILE).tex
	pdflatex $(FILE).tex
	bibtex $(FILE).aux
	pdflatex $(FILE).tex

clean:
	rm -rf *.aux *.dvi *.ps *.blg *.bbl *.log *.out
purge:clean
	rm -rf *.pdf
