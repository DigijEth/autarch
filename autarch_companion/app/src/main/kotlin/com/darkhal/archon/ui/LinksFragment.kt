package com.darkhal.archon.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.darkhal.archon.R
import com.darkhal.archon.util.PrefsManager

class LinksFragment : Fragment() {

    private data class LinkItem(
        val cardId: Int,
        val path: String
    )

    private val links = listOf(
        LinkItem(R.id.card_dashboard, "/dashboard"),
        LinkItem(R.id.card_wireguard, "/wireguard"),
        LinkItem(R.id.card_shield, "/android-protect"),
        LinkItem(R.id.card_hardware, "/hardware"),
        LinkItem(R.id.card_wireshark, "/wireshark"),
        LinkItem(R.id.card_osint, "/osint"),
        LinkItem(R.id.card_defense, "/defense"),
        LinkItem(R.id.card_offense, "/offense"),
        LinkItem(R.id.card_settings, "/settings")
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_links, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val baseUrl = PrefsManager.getAutarchBaseUrl(requireContext())

        // Update server URL label
        view.findViewById<TextView>(R.id.server_url_label).text = "Server: $baseUrl"

        // Set up click listeners for all link cards
        for (link in links) {
            view.findViewById<View>(link.cardId)?.setOnClickListener {
                openUrl("$baseUrl${link.path}")
            }
        }
    }

    private fun openUrl(url: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        startActivity(intent)
    }
}
