package ru.valishin.vpn

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import ru.valishin.vpn.databinding.ActivityMainBinding
import android.net.VpnService

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)


        val button = Button(this).apply { text = "Start VPN" }
        setContentView(button)

        button.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                // If not null, we need to ask the user for permission
                startActivityForResult(intent as Intent, 0)
            } else {
                // Already authorized
                onActivityResult(0, RESULT_OK, null)
            }
        }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            val intent = Intent(this, MyVpnService::class.java)
            startService(intent)
        }
    }

    /**
     * A native method that is implemented by the 'vpn' native library,
     * which is packaged with this application.
     */

}