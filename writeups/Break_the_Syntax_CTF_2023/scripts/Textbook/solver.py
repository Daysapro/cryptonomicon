from Crypto.Util.number import long_to_bytes


n = 21681297669182728074352803263442466828602720333142302446762006692965701217590667073811727774020316753675101387897937957606709604735414772772503037382708861385872320483969852130492098512175180986980539021138682848908549495302818464128432106010638184701774996849671393376895463924808700594336761144020409257869001024705774125138037120854493498205846168091055167537718085782669631600498515013880633422863931918732630368546179505441113203208076467009279895106115068597331057927389872798288089358208231784298821775626006876936567695889100448491196100735610923577273460357520955201454233414599025159271658381501766389770677
g = 21681297669182728074352803263442466828602720333142302446762006692965701217590667073811727774020316753675101387897937957606709604735414772772503037382708861385872320483969852130492098512175180986980539021138682848908549495302818464128432106010638184701774996849671393376895463924808700594336761144020409257869001024705774125138037120854493498205846168091055167537718085782669631600498515013880633422863931918732630368546179505441113203208076467009279895106115068597331057927389872798288089358208231784298821775626006876936567695889100448491196100735610923577273460357520955201454233414599025159271658381501766389770678

flag = 0x0f6afc95ccb6045bd85296b734620f647c273bc6f88dcc25a3bc19e98d051d24041667378e587507d063dd1f0cdde10f412ffb0b56f53284d7d50dcbd94669dbb0d697746fb7a35c8bbe69f68018170de9b54367b95d2270f0b66f6ef77ad7dcc27b90f8aabd0c7b33830343e471d4c59c86f903b664f80d9a5776b19b7f0c65eae6316d51ca0918c5e8319e676f08f3aa4cb7e45166d4c1d30f77ea2edafe9e2fd04b8e7f915ccb6d97d409f742a77c83e6d7b0d488c711841acfc8df706bccba67997adc0a00e5dd96dffb0aaeef87d8fd272dc7b4f82beb8445bd52b1c33990ccd187c45370eafa6560b9bbdece5357313e1e5f275f4b146f200149c44a02e1d36582732daad6d20368a3b8f1e8f7162ed07fbef82b1512788537ca720fb28664b4dac805c877e3e2d64947b2aa61dc303bcd767a2d79da86212642b9de4cebfa4991d9b48f1b090545c3355a740a2d7beb2e0800bc8ebd64f897cd07e42a51059af62fa62d3217407206b424a73e82c0e0a42f1c2ca6716e48c2a8ae8ac2e1a597551f0a6c1762d47d4628c19ae994b0bb754ed6aa1f1c5486b86aa707219dbf827218f5855c41b06e9574d74fc84a70cf1a307762a0df408391495f58babbd2048545285674863ff985056ea5c2b005c9b3e2e07cd705d203359d3e332a846b32c46c5299b822b600ebb3969cb3a236ed6be00fa2f450d5bbb5ade03277

s1_0 = 7124063827524244118567987067718200588118631179272635179021550445094081342568875079774966517588135523364642210818374936874888431770937145319516078247139467258531884622754353539073431767312811359113105521766221552258564245775415327836214781661988679445473371235496836147561417643009875924294666666769701435204009565466687566702716588245922755692558521209143552254004235520407019517079460812551593944598707910054436113454438098298911803287371345214489931906207690687762727625788008587612936371588162225336856660010824297642274537433017078808909431220189272096617405035795150567820104078942118616069008786800734894935244

mu = (s1_0 * pow(-1, -1, n)) % n
phi = pow(mu, -1, n)

assert mu == pow(phi, -1, n)

s1_1 = 10970285536757575596696601711808122806523347157610550373362820875708067899166902698336511312508786486903758467178289675589842196814921974487446949659354238384519573663192058888884948284846965440619972122353811765867002741596354790188286919706218568164342970625378589162110708666880661791149586601725116513975785228649313675871173785430568108443803910278385312951934305340980779108989011050532625607986726433227604729421067863001363681151098553398199294124467096385797166700520347516937461108978220704318785598283754193103334261303321830662665877096855975502855123261323347604565936257393284638441086651262431904485856

s2_1 = 10248445072082616119370788922624159925693428580134286060558143410646737733472218250230605853764264841611284111948779060558054497051693586126835539302184934941178173019031648629468916643217561983545051998965655023147560771173707151167980865132505419457838780431633138154037798054142434100230883949424403963585983791678148146965486329134294912821608479431201037790430653853725302715131433068873747895900059405649428552016297897333683143498503902660240149644805281845008438910200404218282831907845832802843165825688761110986992118592931856918058966261782739286360638167822066605752169535620848793697570548472776090539525

mask = pow(g, s1_1, n ** 2) * pow(s2_1, n, n ** 2) % (n ** 2)

L = (pow(flag, phi, n**2) - 1) // n
u = pow(phi, -1, n)

flagmask = (L * u) % n

flag = (flagmask * pow(mask, -1, n)) % n

print(long_to_bytes(flag))