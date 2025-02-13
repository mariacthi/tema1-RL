1 2 3
# Tudor Maria-Elena 334CC

## TEMA 1 RL - IMPLEMENTARE SWITCH

Limbajul utilizat pentru implementare este python.

## 1. Procesul de comutare.
Am pornit de la pseudocodul prezentat in cerinta temei. Creez mac_table in care
sunt stocate adresele MAC si interfetele pe care au venit.
Cand primesc un pachet, este trecuta adresa sursei in tabela de comutare, precum
si portul de pe care a venit dupa care trebuie verificat tipul adresei destinatie.
Daca aceasta este unicast si exista in tabela, atunci se trimite pachetul catre
acea interfata. Daca una dintre aceste conditii nu este indeplinita, sunt 2 cazuri:
ori adresa este de broadcast ori destinatia nu se gaseste in mac_table. In ambele
cazuri, se vor trimite pachete cate toate interfetele mai putin cea de pe care a
sosit (face flood).

## 2. VLAN
Pornind de la ce am implementat la punctul anterior, am adaugat o verificare a
interfatei de pe care a venit pachetul pentru a afla din ce vlan vine si daca este
de tip trunk sau access. In functie de caz, mi-am creat doua functii send_from_access_mode
si send_from_trunk_mode care verifica interfata pe care se doreste sa se trimita
pachetul. Daca vlan urile sunt de acelasi tip (trunk-trunk sau access-access),
atunci se trimite mesajul mai departe fara vreo modificare, altfel trebuie
adaugat sau scos tag-ul 802.1q in functie de caz.
De asemenea, a fost necesar sa creez si o functie pentru a putea parsa fisierele
de configurare ale switch-urilor: parse_file.

## 3. STP
Am pornit prin a transcrie pseudocodul din enuntul temei, care era in mare parte
cam toata rezolvarea. Daca suntem root bridge trimitem BPDU-uri la fiecare secunda.
Initial toate switch-urile cred ca ele sunt root bridge si isi seteaza porturile de
trunk ca Designated. Pe masura ce isi trimit cadre BPDU intre ele, se stabileste
cine este root bridge dar si tipurile de porturi numite "BLOCKING" sau "LISTENING"
in aceasta tema.
Cel mai greu lucru a fost sa-mi dau seama cum sa trimit cadre BPDU si am decis sa
creez o structura mai simpla a acestora care contine doar field-urile care trebuiau
modificate/verificate: adresa mac de multicast, sender bid, root bid, root cost.
Functia handle_BPDU se ocupa cu algoritmul de STP in sine. Compara root bridge ID-ul
primit de la cadrul BPDU cu root bridge ID-ul pe care il stie switch-ul nostru si in
functie de asta modifica porturile si costurile cailor.
De asemenea, la final cand testam nu imi dadeam seama de ce nu merge implementarea
desi scrisesem tot din pseusocod si mi-am dat seama ca uitam sa fac verificarea in
trimiterea de pachete de la exercitiile anterioare: daca sunt pe un port trunk,
sa ma asigur ca portul nu e blocat.
