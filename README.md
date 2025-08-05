# Cyber Threat Intelligence

Bom, durante a minha carreira, uma das perguntas que mais sou abordado é sobre questões de CTI. Já tem algum tempo que penso em criar um conteúdo sobre isso, mas sempre que começo a escrever sobre, fica grande demais, porque CTI é um assunto muito complexo e não existe fórmula mágica para ser um bom profissional de Threat Hunting. Posso dizer que atuar com Threat Hunting significa estar sempre, sempre estudando e se aperfeiçoando a cada segundo. Às vezes, antes de dormir, começo a me questionar sobre certos incidentes, sobre como poderia ter feito algo diferente, ou me pego pensando no Threat Hunting proativo, imaginando como possivelmente vou encontrar uma ameaça que ainda não foi encontrada. Começo a montar situações na minha cabeça como um quebra-cabeça e refletir sobre elas.

Atuar com Hunting é entender que você tem que estar sempre atualizado, sempre estudando, para que possa estar andando lado a lado com as ameaças. Mas, durante a minha carreira, aprendi que dificilmente você estará exatamente lado a lado. Se estiver apenas alguns passos atrás da ameaça, isso já lhe tornará um grande profissional. Estudar sobre ameaças é fundamental para que você não fique muitos passos distante do atacante.

Quanto mais próximo você estiver das ameaças, mais claramente poderá vê-las. vou dar um exemplo sobre uma ameaça de espionagem sofisticada que afetou dispositivos de segurança, especificamente os firewalls Cisco ASA.

Esses dispositivos são responsáveis por proteger redes governamentais e corporativas, funcionando como barreiras de segurança importantes. No entanto, uma campanha chamada ArcaneDoor, detectada em 2023, mostrou como hackers patrocinados por estados conseguiram explorar duas vulnerabilidades zero-day nesses firewalls para invadir múltiplas redes governamentais globalmente. Esses atacantes conseguiram executar códigos maliciosos nos próprios dispositivos de segurança, espionar o tráfego da rede, roubar dados e manter acesso persistente não apenas por meio de técnicas de software, mas também implantando um pequeno componente de hardware (um tiny chip) diretamente na placa dos firewalls, o que permitiu que o controle malicioso sobrevivesse mesmo após reinicializações e atualizações do sistema.

<img width="870" height="643" alt="{EA4BCFC2-FDD4-4788-A8A0-19902A89B078}" src="https://github.com/user-attachments/assets/bfcac78f-1cd1-4202-a2f5-0ba1306ccec9" />


Esse exemplo reforça uma lição vital para quem atua com Threat Hunting: quanto mais próximo você estiver das ameaças, mais rápido e de forma proativa poderá identificar e remediar ataques desse nível de sofisticação. Entender as técnicas, vulnerabilidades e comportamentos da espionagem permite antecipar ações e reduzir significativamente o impacto nos ambientes protegidos. Estar sempre um passo atrás da ameaça, ao invés de muitos passos, é o que diferencia um bom profissional.

Algumas das perguntas que gosto de me fazer em alguns incidentes é o seguinte

### Quem?
- Usuario envolvido, nome ou ID
- Responsavél como por exemplo após identificar o tipo de comportamento do ataque entender se pertence a algum grupo de ameaça conhecido

### Quando?
- Data/hora da identificação da ameaça e após a analise tentar identificar a data de inicio, pois as vezes você pode ter descoberto na data de hoje, porem já faz mais de 2 anos que a ameaça se encontra lá
- Houve outros eventos correlacionados desde a data de inicio até a data que você identificou?

### Onde?
- Localização do Host no caso onde eles está localizado dentro da empresa? pois as vezes pode ser que você esteja investigando um host que por exemplo é um host de linha de produção que normalmente são host que são extremamente vulneraveis por serem de ambiente legado ou as vezes é um host onde os funcionarios tem livre acesso para utilizar durante o intervalo e todo mundo usa, ou as vezes o host se trata de algum hardware como impressora ou camera, então saber onde está e o que é, é algo muito importante


### Por que?
- Qual a motivação? (Financeira, espionagem, hacktivismo)
- Esse ativo é valioso para o atacante? entender se o ativo é valioso para o atacante é algo muito importante entender quais as informações que a dentro daquele ativo e sua importancia dentro do ambiente, pois já atuei em casos que ao analisar o comportamento do atacante ficava claro que o dispositivo não tinha tanta importancia para o atacante pois ele tinha outros dispositivos em seu comando dentro do ambiente, então ele estava apenas queimando um dispositivo dentro do ambiente e não via problema em perder acesso aquele dispositivo, isso ocorre e conseguir identificar isso é importante.


### Como?
- Qual vetor de ataque foi usado? (malware, phishing, rdp)
- Qual técnica foi aplicada? (movimentação lateral?, exfiltração?)



