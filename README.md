# Cyber Threat Intelligence

Bom, durante a minha carreira, uma das perguntas que mais sou abordado é sobre questões de CTI. Já tem algum tempo que penso em criar um conteúdo sobre isso, mas sempre que começo a escrever sobre, fica grande demais, porque CTI é um assunto muito complexo e não existe fórmula mágica para ser um bom profissional de Threat Hunting. Posso dizer que atuar com Threat Hunting significa estar sempre, sempre estudando e se aperfeiçoando a cada segundo. Às vezes, antes de dormir, começo a me questionar sobre certos incidentes, sobre como poderia ter feito algo diferente, ou me pego pensando no Threat Hunting proativo, imaginando como possivelmente vou encontrar uma ameaça que ainda não foi encontrada. Começo a montar situações na minha cabeça como um quebra-cabeça e refletir sobre elas.

Atuar com Hunting é entender que você tem que estar sempre atualizado, sempre estudando, para que possa estar andando lado a lado com as ameaças. Mas, durante a minha carreira, aprendi que dificilmente você estará exatamente lado a lado. Se estiver apenas alguns passos atrás da ameaça, isso já lhe tornará um grande profissional. Estudar sobre ameaças é fundamental para que você não fique muitos passos distante do atacante.

Quanto mais próximo você estiver das ameaças, mais claramente poderá vê-las. vou dar um exemplo sobre uma ameaça de espionagem sofisticada que afetou dispositivos de segurança, especificamente os firewalls Cisco ASA.

Esses dispositivos são responsáveis por proteger redes governamentais e corporativas, funcionando como barreiras de segurança importantes. No entanto, uma campanha chamada ArcaneDoor, detectada em 2023, mostrou como hackers patrocinados por estados conseguiram explorar duas vulnerabilidades zero-day nesses firewalls para invadir múltiplas redes governamentais globalmente. Esses atacantes conseguiram executar códigos maliciosos nos próprios dispositivos de segurança, espionar o tráfego da rede, roubar dados e manter acesso persistente não apenas por meio de técnicas de software, mas também implantando um pequeno componente de hardware (um tiny chip) diretamente na placa dos firewalls, o que permitiu que o controle malicioso sobrevivesse mesmo após reinicializações e atualizações do sistema.

<img width="870" height="643" alt="{EA4BCFC2-FDD4-4788-A8A0-19902A89B078}" src="https://github.com/user-attachments/assets/bfcac78f-1cd1-4202-a2f5-0ba1306ccec9" />


Esse exemplo reforça uma lição vital para quem atua com Threat Hunting: quanto mais próximo você estiver das ameaças, mais rápido e de forma proativa poderá identificar e remediar ataques desse nível de sofisticação. Entender as técnicas, vulnerabilidades e comportamentos da espionagem permite antecipar ações e reduzir significativamente o impacto nos ambientes protegidos. Estar sempre um passo atrás da ameaça, ao invés de muitos passos, é o que diferencia um bom profissional.

Algumas das perguntas que gosto de me fazer em alguns incidentes para coletar e analisar
### Quem?
- Nome, usuario ou ID
- Responsavél como por exemplo após identificar o tipo de comportamento do ataque entender se pertence a algum grupo de ameaça conhecido

### Quando?
- Data/hora da identificação da ameaça e após a analise tentar identificar a data de inicio, pois as vezes você pode ter descoberto na data de hoje, porem já faz mais de 2 anos que a ameaça se encontra lá
- Houve outros eventos correlacionados desde a data de inicio até a data que você identificou?

### Onde?
- Identificar o Host interno é algo muito importante pois a varias variaveis para essa situação pois as vezes pode ser que você esteja investigando um host que por exemplo é um host de linha de produção que normalmente são host que são extremamente vulneraveis por serem de ambiente legado ou as vezes é um host onde os funcionarios tem livre acesso e todo mundo usa o que abre porta para varias possibilidades como um insider, ou até mesmo trata-se de um host utilizado para pentest, identificar o host é algo importnate pois isso faz com que você também possa saber a importancia daquele host, pois em um ambiente comprometido uma das coisas que você vai querer é isolar o host para que o atacante perca o acesso e possa realizar a pericia e se o host se tratar de um host muito critico você não poderá isolar o host, então saber que tipo de host é e onde está é algo importante, assim você pode saber até onde suas ações podem ir, podem ir dentro do host e até onde sua infraestrutura está comprometida.
- Indetificar o host do Atacante também é algo importante por exemplo saber o dominio do atacante IP e localização.

### Por que?
- Qual a motivação? (Financeira, espionagem, hacktivismo)
- Esse ativo é valioso para o atacante? entender se o ativo é valioso para o atacante é algo muito importante entender quais as informações que a dentro daquele ativo e sua importancia dentro do ambiente, pois já atuei em casos que ao analisar o comportamento do atacante ficava claro que o dispositivo não tinha tanta importancia e ele tinha outros dispositivos em seu comando dentro do ambiente, então ele estava apenas queimando um dispositivo dentro do ambiente e não via problema em perder acesso aquele dispositivo pois aquele dispositivo não era tão valioso e o mesmo havia identificado isso também, isso ocorre e conseguir identificar isso é importante pois baseado no comportamento do atacante você consegue identificar se o mesmo está apenas queimando aquele dispositivo para coletar informações.


### Como?
- Qual vetor de ataque foi usado? (malware, phishing, rdp)
- Qual técnica foi aplicada? (movimentação lateral?, exfiltração?)


Bom então vamos dar a situação que estamos com um incidente em mãos mas não temos o usuario que fez isso, pois uma coisa comum em situações de um ataque é o escalonamento de privilegio e bom você viu o incidente e após analisar viu que tudo está sendo feito pelo usuario root, bom já um dos EDRs mais usados no mundo é o Falcon, vamos dar um exemplo que estamos em um ambiente que utiliza Falcon então eu gosto de iniciar com uma query para analisar os ultimos logons feitos no host

## Logons
```text
#event_simpleName=UserLogon
| UserUUID:=UserSid | UserUUID:=UID
| groupBy([aid], function=([selectFromMax(field="@timestamp", include=[ComputerName, UserUUID, UserName, LogonType, @timestamp])]))
| $falcon/helper:enrich(field=LogonType)
| aid=~match(file="aid_master_main.csv", column=[aid])
```

Bom após analisar os Logons e ter feito a coleta dos mesmo gosto de analisar as commandlines

## Host Linux - Last commands removing other tools from path (+clean)
```text
#event_simpleName="*Process*"
| aid=?aid
| CommandLine=?CommandLine
| (ImageFileName!=*CrowdStrike*) AND (ImageFileName!=*guardicore*) //Paths to exclude from filter
| UserName!=zabbix* //User to exclude from filter
| table([@timestamp, UserName, ImageFileName, CommandLine, SHA256HashData, #event_simpleName], limit=1000)
```

Bom após analisar as commandlines muitas vezes estaremos munidos de informações, e agora teremos de fazer o filtro e separar quais informações são relevantes ou não, por isso em minha query eu já as vezes descarto alguns usuarios, como por exemplo em minha query acima descartei o user zabbix, mas você deve levar em consideração que o fato disso é apenas para que o filtro fique mais limpo, mas o que lhe garante que o user "zabbix" não tenha sido comprometido? então você deve ter muito cuidado ao aplicar filtros.

Outra coisa que gosto de fazer é validar as comunicações do host que estou investigando com ambientes externos para isso uso a seguinte query

## Connections to External Addresses
```text
#event_simpleName=NetworkConnect*
| aid=?aid
| RemotePort=?RemotePort
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| table([ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, @timestamp], limit=1000)
```

Então digamos que bom tenho o IP em mãos que foi o ator malicioso e tenho as execuções aplicadas e eu quero ver todas as ações daquele IP no Host que foi o alvo então usarei uma das querys abaixo

## Activities of an IP on the Host
```text
#event_simpleName=Network* AND RemoteAddressIP4=
| aid=?aid
```
//OR
```text
#event_simpleName=Network* AND RemoteIP=*
| aid=?aid
| table(fields = [ComputerName, #event_simpleName, ContextBaseFileName, RemoteIP, RemotePort, LocalIP, LocalPort, ConnectionDirection, @timestamp])
```

Bom então dei um exemplo simples acima para que você saiba como iniciar sua investigação sobre um caso, mas cada caso tem um nivel de complexibilidade e alguns mais complexibilidade outros menos, alguns podem ser resolvidos em apenas algumas horas alguns podem levar dias ou meses, e sua corrida é contra o tempo.

Neste repositorio deixei um pasta onde tem algumas querys do CS Falcon que podem ser uteis em suas investigações [Querys Falcon](FALCON-queries.md)

Aqui também vai um repositorio que contem mais de 170 ferramentas para consultas de IPs, Hash, IOC, grupos e outros auxiliares nas suas investigações como auxiliares para identificar grupos APT, ou rastreamento de blockchain etc... 🔗 [Repositorio com ferramentas auxiliares](https://github.com/sculptormoon/blue-team-auxiliary)

🔗 [Confira este repositorio sobre Threat Intelligence](https://github.com/sculptormoon/Threat-Intelligence)

Bom em meu perfil a diversos repositorio que podem ser uteis em suas investigações como repositorios voltados a analise de malware e outros.

Esse repositorio trata-se de um pequeno contexto sobre CTI, pois como informei lá em cima CTI é um assunto complexo e para você ser um bom profissional de CTI deve dominar varias tecnicas como engenharia reversa, técnicas de forense, conhecimento profundo sobre metodologias de ataque, comprensão sobre questões comportamentais voltadas a ataque e espionagem, então espero que esse repositorio possa lhe ajudar a se guiar para se tornar um bom analista de CTI.


## License

This repository is licensed under the MIT License. The license covers the content of this repository, which consists of links and related information. See the [LICENSE](LICENSE) file for more details.

## Author
### Lucas Benites.

## Contact
If you have any questions or need more information, feel free to contact me through my GitHub profile [perfil GitHub](https://github.com/sculptormoon).


