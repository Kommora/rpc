package main

import (
	"log"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"bufio"
	"bytes"
	"errors"
	"net/rpc"
	"fmt"
	"strconv"
	"strings"
)

type Produto struct{
	Nome, Id, Categoria, Descricao string
	Preco float32
	Quantidade int
}

type Novo struct{
	P1,P2 Produto
}
type Usuario struct {
	Login, Senha []byte
}

func GerarChavePbPv(){
	pv,_:=rsa.GenerateKey(rand.Reader,2048)
	pvBytes:=x509.MarshalPKCS1PrivateKey(pv)
	pbBytes,err:=x509.MarshalPKIXPublicKey(&pv.PublicKey)
	checkErro(err)

	pvPem:=pem.EncodeToMemory(
		&pem.Block{
			Type:"Private key",
			Bytes:pvBytes},
	)

	pbPem:=pem.EncodeToMemory(
		&pem.Block{
			Type:"Public key",
			Bytes:pbBytes},
	)

	txt,err:=os.Create("cliente/pvA.txt")
	checkErro(err)
	t1:=bufio.NewWriter(txt)
	t1.WriteString(string(pvPem))
	t1.Flush()

	txt,err=os.Create("cliente/pbA.txt")
	checkErro(err)
	t1=bufio.NewWriter(txt)
	t1.WriteString(string(pbPem))
	t1.Flush()
}

func encriptarMsg(email string,senha string)([]byte,[]byte,error)  {
	txt,err:=os.Open("servidor/pbB.txt")
	checkErro(err)
	buf:=new(bytes.Buffer)
	buf.ReadFrom(txt)
	keyBuf:=buf.String()

	key,_:=pem.Decode([]byte(keyBuf))
	pbKey,_:=x509.ParsePKIXPublicKey(key.Bytes)

	switch pub := pbKey.(type) {
	case *rsa.PublicKey:
		crEmail,err:=rsa.EncryptPKCS1v15(rand.Reader,pub,[]byte(email))
		checkErro(err)
		crSenha,err:=rsa.EncryptPKCS1v15(rand.Reader,pub,[]byte(senha))
		checkErro(err)
		return crEmail,crSenha,nil
	default:
		break
	}
	return nil,nil,errors.New("Impossivel")
}

func decriptar(msg []byte)(string)  {

	txt,err:=os.Open("cliente/pvA.txt")
	checkErro(err)
	buf:=new(bytes.Buffer)
	buf.ReadFrom(txt)
	keyBuf:=buf.String()

	key,_:=pem.Decode([]byte(keyBuf))

	pvKey,_:=x509.ParsePKCS1PrivateKey(key.Bytes)
	decriptado,_:=rsa.DecryptPKCS1v15(rand.Reader,pvKey,msg)

	return string(decriptado)
}

func menu(con *rpc.Client)  {
	leitor:=bufio.NewReader(os.Stdin)
	for {
		fmt.Println("1- Inserir no banco")
		fmt.Println("2- Requisitar um produto no banco")
		fmt.Println("3- Atualizar um produto no banco")
		fmt.Println("4- Remover um produto no banco")
		fmt.Println("0- sair do programa")
		item,err:=leitor.ReadString('\n')
		checkErro(err)
		switch item {
		case "1\n":
			fmt.Println("\nOpcao 1 Selecionada")
			pdt:=Produto{}
			fmt.Println("Digite nome do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Nome=item
			fmt.Println("Digite o preco do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			num,err:=strconv.ParseFloat((strings.Split(item,"\n"))[0],32)
			checkErro(err)
			pdt.Preco=float32(num)
			fmt.Println("Digite a quantidade do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			num,err=strconv.ParseFloat((strings.Split(item,"\n"))[0],32)
			checkErro(err)
			pdt.Quantidade=int(num)
			fmt.Println("Digite a categoria do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Descricao=item
			fmt.Println("Digite a descricao do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Categoria=item
			fmt.Println("Digite o ID do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Id=item
			fmt.Println("Enviando para o banco de dados")
			var replay bool
			err=con.Call("Crud.Create",pdt,&replay)
			checkErro(err)
			if replay==true{
				fmt.Println("Produto armazenado")
			}else {
				fmt.Println("Produto nao armazenado")
			}
		case "2\n":
			fmt.Println("\nOpcao 2 Selecionada")
			pdt:=Produto{"","","","",0,0}
			fmt.Println("Digite o ID do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Id=item
			var replay Produto
			err=con.Call("Crud.Request",pdt,&replay)
			checkErro(err)
			if replay.Id!=""{
				fmt.Println("Produto buscado")
				fmt.Println("Nome:"+replay.Nome)
				fmt.Println("Preço:"+strconv.FormatFloat(float64(replay.Preco),'f',2,64))
				fmt.Println("Quantidade:"+strconv.Itoa(replay.Quantidade))
				fmt.Println("Categoria:"+replay.Categoria)
				fmt.Println("Descrição:"+replay.Descricao)
				fmt.Println("ID:"+replay.Id)
			}else {
				fmt.Println("Produto nao buscado")
			}
		case "3\n":
			fmt.Println("\nOpcao 2 Selecionada")
			pdt:=Produto{}
			pdt1:=Produto{}
			fmt.Println("Digite o id do produto atualizar")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt1.Id=item
			fmt.Println("Digite nome do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Nome=item
			fmt.Println("Digite o preco do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			num,err:=strconv.ParseFloat((strings.Split(item,"\n"))[0],32)
			checkErro(err)
			pdt.Preco=float32(num)
			fmt.Println("Digite a quantidade do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			num,err=strconv.ParseFloat((strings.Split(item,"\n"))[0],32)
			checkErro(err)
			pdt.Quantidade=int(num)
			fmt.Println("Digite a categoria do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Descricao=item
			fmt.Println("Digite a descricao do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Categoria=item
			fmt.Println("Digite o ID do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Id=item
			fmt.Println("Enviando para o banco de dados")
			var replay bool
			args:=Novo{pdt1,pdt}
			err=con.Call("Crud.Update",args,&replay)
			checkErro(err)
			if replay==true{
				fmt.Println("Produto atualizado")
			}else {
				fmt.Println("Produto nao atualizado")
			}
		case "4\n":
			fmt.Println("\nOpcao 4 Selecionada")
			pdt:=Produto{"","","","",0,0}
			fmt.Println("Digite o ID do produto")
			item,err=leitor.ReadString('\n')
			checkErro(err)
			pdt.Id=item
			var replay bool
			err=con.Call("Crud.Delete",pdt,&replay)
			checkErro(err)
			if replay==true{
				fmt.Println("Produto Deletado")
			}else {
				fmt.Println("Produto nao encontrado")
			}
		case "0\n":
			fmt.Println("\nOpcao 0 Selecionada")
			var replay bool
			err:=con.Call("Crud.Deslogar",Usuario{[]byte("afonso@lindo.gostoso"),[]byte("6996")},&replay)
			checkErro(err)
			if replay==true{
				fmt.Println("até")
			}else {
				fmt.Println("login ou senha errada")
			}
			os.Exit(1)
		default:
			fmt.Println("Item errado")
		}
	}
}

func main() {
	fmt.Println("Abrindo a conexao")
	con, err := rpc.Dial("tcp", "localhost:5555")
	checkErro(err)
	fmt.Println("Conexao realizada com sucesso")
	GerarChavePbPv()
	email,senha,err:=encriptarMsg("afonso@lindo.belo","6996")
	checkErro(err)
	args:=Usuario{email,senha}
	var replay []byte
	fmt.Println("Email:afonso@lindo.gostoso\nSenha:6996")
	fmt.Println("enviando login e senha")
	err=con.Call("User.Login",args,&replay)
	checkErro(err)
	if decriptar(replay)=="ok" {
		fmt.Println("logado com sucesso\n")
		menu(con)
	}else {
		fmt.Println("login incorreto")
		os.Exit(1)
	}
}

func checkErro(err error)  {
	if err!=nil{
		log.Fatal("error:", err)
	}
}